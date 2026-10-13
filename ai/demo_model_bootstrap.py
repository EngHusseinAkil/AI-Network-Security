"""Secure orchestration for the deterministic development demonstration model."""
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from ai.data_loader import load_sample_dataset
from ai.inference import InferenceEngine
from ai.model_persistence import load_model_artifact, save_model_artifact
from ai.model_registry import ModelRegistry
from ai.preprocessing import prepare_dataset
from ai.training import train_random_forest
from utils.exceptions import ValidationError


DEMO_MODEL_VERSION = "demo-1.0.0"
_DEMO_VERSION_PATTERN = re.compile(r"^demo-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True, slots=True)
class DemoModelBootstrapResult:
    model_version: str
    dataset_path: str
    sample_count: int
    labels: tuple[str, ...]
    algorithm: str
    artifact_directory: str
    files_created: tuple[str, ...]
    registration_result: str
    active_model_version: str
    smoke_inference: dict[str, Any]
    evaluation_limitation: str


def bootstrap_demo_model(
    dataset_path: Path,
    models_dir: Path,
    model_version: str = DEMO_MODEL_VERSION,
) -> DemoModelBootstrapResult:
    """Build, validate, register, activate, and smoke-test a trusted CSV demo model."""
    dataset_path = Path(dataset_path).resolve()
    models_dir = Path(models_dir).resolve()
    if not _DEMO_VERSION_PATTERN.fullmatch(model_version):
        raise ValidationError(
            "Demo model version must start with 'demo-' and contain only safe "
            "letters, digits, dots, underscores, or hyphens."
        )

    artifact_dir = models_dir / f"model_{model_version}"
    registry_path = models_dir / "registry.json"
    registry = ModelRegistry(str(registry_path))
    if artifact_dir.exists() or model_version in registry.list_models():
        raise ValidationError(
            f"Model version '{model_version}' already exists. Overwrite is forbidden. "
            "Use a new --model-version. In a disposable development workspace, stop "
            "the application, back up required evidence, and remove the complete "
            "artifact/registry workspace before rebuilding; never edit registry.json."
        )

    dataset = load_sample_dataset(dataset_path, schema_type="flow")
    if dataset["row_count"] == 0:
        raise ValidationError("Dataset contains no samples.")
    prepared = prepare_dataset(dataset)
    label_counts = Counter(dataset["labels"])
    stratification_possible = all(count >= 2 for count in label_counts.values())

    training = train_random_forest(
        prepared,
        allow_unstratified_fallback_for_tests=not stratification_possible,
    )
    if stratification_possible:
        evaluation_limitation = (
            "Evaluation was omitted from this bootstrap command; use the separately "
            "approved evaluation workflow before making performance claims."
        )
    else:
        evaluation_limitation = (
            "Evaluation skipped: one or more classes have fewer than two samples, "
            "so a representative stratified holdout is impossible. No accuracy or "
            "production-performance claim is valid."
        )

    saved_dir = Path(save_model_artifact(
        training,
        evaluation_result=None,
        destination_dir=str(models_dir),
        model_version=model_version,
    )).resolve()

    # Only the just-created trusted artifact is deserialized, after manifest hashes
    # and compatibility metadata have been validated by the secure loader.
    loaded = load_model_artifact(str(saved_dir))
    registry.register_model(model_version, str(saved_dir), loaded["metadata"])
    registry.activate_model(model_version)

    engine = InferenceEngine.from_active_registry(str(registry_path))
    smoke = engine.predict_one(dataset["features"][0])
    safe_smoke = {
        "predicted_canonical_label": smoke["predicted_canonical_label"],
        "confidence_score": smoke["confidence_score"],
        "risk_score": smoke["risk_score"],
        "model_version": smoke["model_version"],
    }

    return DemoModelBootstrapResult(
        model_version=model_version,
        dataset_path=str(dataset_path),
        sample_count=dataset["row_count"],
        labels=tuple(sorted(label_counts)),
        algorithm=training["model_metadata"]["model_family"],
        artifact_directory=str(saved_dir),
        files_created=tuple(sorted(path.name for path in saved_dir.iterdir())),
        registration_result="registered",
        active_model_version=registry.get_active_model_version(),
        smoke_inference=safe_smoke,
        evaluation_limitation=evaluation_limitation,
    )
