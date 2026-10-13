import json
from pathlib import Path

import pytest

from ai.demo_model_bootstrap import bootstrap_demo_model
from ai.inference import InferenceEngine
from ai.model_persistence import generate_sha256, load_model_artifact
from ai.model_registry import ModelRegistry
from backend.app_factory import create_app
from utils.exceptions import ValidationError


HEADER = (
    "duration,packet_count,byte_count,min_packet_size,max_packet_size,"
    "avg_packet_size,protocol_enc,direction_enc,label"
)
ROWS = (
    "1.5,10,1500,64,150,150.0,1,2,benign",
    "0.1,5,500,64,100,100.0,2,2,benign",
    "10.0,10000,640000,64,64,64.0,1,3,ddos",
    "0.5,50,3200,64,64,64.0,1,2,port_scan",
    "0.2,20,1280,64,64,64.0,1,2,port_scan",
    "12.0,2,128,64,64,64.0,1,2,brute_force",
    "1.2,12,2000,64,500,166.6,1,2,benign",
    "0.01,2,128,64,64,64.0,3,2,benign",
)


def _write_dataset(path, header=HEADER, rows=ROWS):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join((header, *rows)) + "\n", encoding="utf-8")
    return path


def _app(tmp_path):
    data_dir = tmp_path / "data"
    models_dir = tmp_path / "models"
    _write_dataset(data_dir / "samples" / "tiny_flow_sample.csv")
    return create_app({
        "TESTING": True,
        "ENVIRONMENT": "development",
        "DATA_DIR": data_dir,
        "MODELS_DIR": models_dir,
        "SECRET_KEY": "test-only-demo-model-secret",
    })


def test_demo_model_command_appears_in_help(tmp_path):
    app = _app(tmp_path)
    result = app.test_cli_runner().invoke(args=["demo", "--help"])
    assert result.exit_code == 0
    assert "model" in result.output


def test_successful_bootstrap_creates_integral_active_artifact_and_smoke_result(
    tmp_path,
):
    app = _app(tmp_path)
    result = app.test_cli_runner().invoke(args=["demo", "model"])
    assert result.exit_code == 0, result.output
    assert "model_version: demo-1.0.0" in result.output
    assert "sample_count: 8" in result.output
    assert "benign, brute_force, ddos, port_scan" in result.output
    assert "algorithm: RandomForestClassifier" in result.output
    assert "registration_result: registered" in result.output
    assert "active_model_version: demo-1.0.0" in result.output
    assert "smoke_inference:" in result.output
    assert "not production-ready" in result.output
    assert "representative stratified holdout is impossible" in result.output

    models_dir = Path(app.config["MODELS_DIR"])
    artifact_dir = models_dir / "model_demo-1.0.0"
    assert {path.name for path in artifact_dir.iterdir()} == {
        "estimator.joblib", "metadata.json", "manifest.json",
    }
    assert not (artifact_dir / "evaluation.json").exists()

    manifest = json.loads(
        (artifact_dir / "manifest.json").read_text(encoding="utf-8")
    )
    for filename, digest in manifest["files"].items():
        assert generate_sha256(str(artifact_dir / filename)) == digest

    loaded = load_model_artifact(str(artifact_dir))
    assert loaded["evaluation"] is None
    registry = ModelRegistry(str(models_dir / "registry.json"))
    assert "demo-1.0.0" in registry.list_models()
    assert registry.get_active_model_version() == "demo-1.0.0"
    smoke = InferenceEngine.from_active_registry(
        str(models_dir / "registry.json")
    ).predict_one({
        "duration": 1.5,
        "packet_count": 10,
        "byte_count": 1500,
        "min_packet_size": 64,
        "max_packet_size": 150,
        "avg_packet_size": 150.0,
        "protocol_enc": 1,
        "direction_enc": 2,
    })
    assert smoke["model_version"] == "demo-1.0.0"


def test_bootstrap_updates_dashboard_health_and_simulation(tmp_path):
    app = _app(tmp_path)
    result = app.test_cli_runner().invoke(args=["demo", "model"])
    assert result.exit_code == 0, result.output

    models = app.extensions["dependencies"].model_service.get_models()
    assert models["count"] == 1
    assert models["models"][0]["active"] is True
    assert models["models"][0]["model_version"] == "demo-1.0.0"

    health = app.extensions["dependencies"].ai_health_service.get_health_summary()
    assert health["overall_status"] == "pass"
    assert health["readiness_level"] == "integration_ready"

    simulation = app.extensions[
        "dependencies"
    ].monitoring_simulation_service.simulate_flow({
        "duration": 1.5,
        "packet_count": 10,
        "byte_count": 1500,
        "min_packet_size": 64,
        "max_packet_size": 150,
        "avg_packet_size": 150.0,
        "protocol_enc": 1,
        "direction_enc": 2,
    })
    assert simulation["state"] == "simulation_complete"
    assert simulation["safe_error_category"] is None

    response = app.test_client().get("/dashboard/models")
    assert response.status_code == 200
    assert b"demo-1.0.0" in response.data


def test_production_refusal(tmp_path):
    app = _app(tmp_path)
    app.config["ENVIRONMENT"] = "production"
    result = app.test_cli_runner().invoke(args=["demo", "model"])
    assert result.exit_code != 0
    assert "unavailable in production" in result.output
    assert not (Path(app.config["MODELS_DIR"]) / "model_demo-1.0.0").exists()


@pytest.mark.parametrize(
    ("name", "header", "rows", "message"),
    [
        ("empty.csv", HEADER, (), "contains no samples"),
        (
            "schema.csv",
            HEADER.replace("duration,packet_count", "packet_count,duration"),
            ROWS,
            "schema order exactly",
        ),
        (
            "numeric.csv",
            HEADER,
            (ROWS[0].replace("1.5", "not-a-number", 1), *ROWS[1:]),
            "non-numeric",
        ),
        (
            "label.csv",
            HEADER,
            (ROWS[0].replace("benign", "not_canonical"), *ROWS[1:]),
            "not supported",
        ),
    ],
)
def test_invalid_datasets_fail_safely(tmp_path, name, header, rows, message):
    app = _app(tmp_path)
    dataset = _write_dataset(tmp_path / name, header, rows)
    result = app.test_cli_runner().invoke(
        args=["demo", "model", "--dataset", str(dataset)]
    )
    assert result.exit_code != 0
    assert message.casefold() in result.output.casefold()
    assert not (Path(app.config["MODELS_DIR"]) / "model_demo-1.0.0").exists()


def test_missing_dataset_fails_safely(tmp_path):
    app = _app(tmp_path)
    result = app.test_cli_runner().invoke(args=[
        "demo", "model", "--dataset", str(tmp_path / "missing.csv"),
    ])
    assert result.exit_code != 0
    assert "Dataset path does not exist" in result.output


def test_existing_version_refuses_overwrite_with_safe_guidance(tmp_path):
    app = _app(tmp_path)
    runner = app.test_cli_runner()
    assert runner.invoke(args=["demo", "model"]).exit_code == 0
    second = runner.invoke(args=["demo", "model"])
    assert second.exit_code != 0
    assert "Overwrite is forbidden" in second.output
    assert "Use a new --model-version" in second.output
    assert "never edit registry.json" in second.output


def test_bootstrap_is_deterministic(tmp_path):
    dataset = _write_dataset(tmp_path / "tiny.csv")
    first = bootstrap_demo_model(dataset, tmp_path / "models-a")
    second = bootstrap_demo_model(dataset, tmp_path / "models-b")
    assert first.labels == second.labels
    assert first.sample_count == second.sample_count == 8
    assert first.algorithm == second.algorithm == "RandomForestClassifier"
    assert first.smoke_inference == second.smoke_inference

    first_loaded = load_model_artifact(first.artifact_directory)
    second_loaded = load_model_artifact(second.artifact_directory)
    first_meta = first_loaded["metadata"]["model_metadata"]
    second_meta = second_loaded["metadata"]["model_metadata"]
    assert first_meta["random_seed"] == second_meta["random_seed"] == 42
    assert first_meta["class_distribution_train"] == second_meta[
        "class_distribution_train"
    ]
    assert first_meta["class_distribution_test"] == second_meta[
        "class_distribution_test"
    ]
