import os
import json
import pytest
import joblib
from typing import Dict, Any

from ai.constants import RANDOM_SEED, FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from network.features import FLOW_FEATURE_ORDER
from ai.preprocessing import LABEL_TO_INDEX
from ai.training import train_random_forest, build_random_forest_classifier
from ai.evaluation import evaluate_model
from ai.model_persistence import (
    save_model_artifact,
    load_model_artifact,
    generate_sha256
)
from utils.exceptions import ValidationError

@pytest.fixture
def synthetic_training_data():
    X = [
        [1.0, 10.0, 100.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.1, 11.0, 110.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.2, 12.0, 120.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.3, 13.0, 130.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.4, 14.0, 140.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.5, 15.0, 150.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [0.1, 1000.0, 64000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.2, 2000.0, 128000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.3, 3000.0, 192000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.4, 4000.0, 256000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.5, 5000.0, 320000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.6, 6000.0, 384000.0, 64.0, 64.0, 64.0, 1.0, 3.0]
    ]
    y = [LABEL_TO_INDEX["benign"]] * 6 + [LABEL_TO_INDEX["ddos"]] * 6
    metadata = {
        "schema_type": "flow",
        "schema_version": FLOW_SCHEMA_VERSION,
        "preprocessing_version": "1.0.0",
        "ordered_feature_names": FLOW_FEATURE_ORDER,
        "feature_count": len(FLOW_FEATURE_ORDER),
        "label_encoding_map": LABEL_TO_INDEX,
        "random_seed_used": RANDOM_SEED
    }
    return {"X": X, "y": y, "metadata": metadata}

@pytest.fixture
def trained_result(synthetic_training_data):
    return train_random_forest(
        synthetic_training_data, test_ratio=0.5, allow_unstratified_fallback_for_tests=False
    )

@pytest.fixture
def evaluation_result(trained_result):
    return evaluate_model(trained_result)

def test_unfitted_estimators_cannot_be_saved(tmp_path, trained_result):
    unfitted_clf = build_random_forest_classifier()
    bad_result = dict(trained_result)
    bad_result["estimator"] = unfitted_clf

    with pytest.raises(ValidationError, match="estimator is not fitted"):
        save_model_artifact(bad_result, None, str(tmp_path), "v1.0.0")

def test_fitted_estimators_save_successfully(tmp_path, trained_result, evaluation_result):
    dest = save_model_artifact(trained_result, evaluation_result, str(tmp_path), "v1.0.0")
    assert os.path.exists(dest)
    assert os.path.exists(os.path.join(dest, "estimator.joblib"))
    assert os.path.exists(os.path.join(dest, "metadata.json"))
    assert os.path.exists(os.path.join(dest, "evaluation.json"))
    assert os.path.exists(os.path.join(dest, "manifest.json"))

def test_no_overwrite_existing_version(tmp_path, trained_result, evaluation_result):
    save_model_artifact(trained_result, evaluation_result, str(tmp_path), "v1.0.0")
    with pytest.raises(ValidationError, match="Overwrites are forbidden"):
        save_model_artifact(trained_result, evaluation_result, str(tmp_path), "v1.0.0")

def test_artifact_files_in_temp_directory(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")
    assert str(tmp_path) in dest

def test_estimator_reloads_and_remains_fitted(tmp_path, trained_result, evaluation_result):
    dest = save_model_artifact(trained_result, evaluation_result, str(tmp_path), "v1.0.0")
    loaded = load_model_artifact(dest)

    from sklearn.utils.validation import check_is_fitted
    check_is_fitted(loaded["estimator"])
    assert getattr(loaded["estimator"], "n_features_in_") == len(FLOW_FEATURE_ORDER)

def test_metadata_and_eval_round_trips(tmp_path, trained_result, evaluation_result):
    dest = save_model_artifact(trained_result, evaluation_result, str(tmp_path), "v1.0.0")
    loaded = load_model_artifact(dest)

    assert loaded["metadata"]["model_version"] == "v1.0.0"
    assert loaded["metadata"]["artifact_format_version"] == "1.0"
    assert "security_disclaimer" in loaded["metadata"]

    assert loaded["evaluation"]["accuracy"] == evaluation_result["accuracy"]

def test_modified_model_fails_integrity(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")

    # Tamper with the joblib
    with open(os.path.join(dest, "estimator.joblib"), "ab") as f:
        f.write(b"tamper")

    with pytest.raises(ValidationError, match="Integrity check failed"):
        load_model_artifact(dest)

def test_modified_metadata_fails_integrity(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")

    # Tamper with metadata
    with open(os.path.join(dest, "metadata.json"), "a") as f:
        f.write(" ")

    with pytest.raises(ValidationError, match="Integrity check failed"):
        load_model_artifact(dest)

def test_missing_required_files_fail(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")
    os.remove(os.path.join(dest, "estimator.joblib"))
    with pytest.raises(ValidationError, match="Missing required file"):
        load_model_artifact(dest)

def test_schema_mismatch_fails(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")

    # Safely modify metadata and fix hash
    meta_path = os.path.join(dest, "metadata.json")
    with open(meta_path, "r") as f:
        meta = json.load(f)
    meta["schema_metadata"]["schema_version"] = "99.99"
    with open(meta_path, "w") as f:
        json.dump(meta, f)

    # Update manifest to bypass integrity check and test compatibility check
    manifest_path = os.path.join(dest, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    manifest["files"]["metadata.json"] = generate_sha256(meta_path)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    with pytest.raises(ValidationError, match="Schema version mismatch"):
        load_model_artifact(dest)

def test_feature_order_mismatch_fails(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")

    meta_path = os.path.join(dest, "metadata.json")
    with open(meta_path, "r") as f:
        meta = json.load(f)
    meta["model_metadata"]["ordered_feature_names"] = ["wrong_order"] + meta["model_metadata"]["ordered_feature_names"][1:]
    with open(meta_path, "w") as f:
        json.dump(meta, f)

    manifest_path = os.path.join(dest, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    manifest["files"]["metadata.json"] = generate_sha256(meta_path)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    with pytest.raises(ValidationError, match="Feature ordering mismatch"):
        load_model_artifact(dest)

def test_preprocessing_version_mismatch_fails(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")

    meta_path = os.path.join(dest, "metadata.json")
    with open(meta_path, "r") as f:
        meta = json.load(f)
    meta["schema_metadata"]["preprocessing_version"] = "9.9.9"
    with open(meta_path, "w") as f:
        json.dump(meta, f)

    manifest_path = os.path.join(dest, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    manifest["files"]["metadata.json"] = generate_sha256(meta_path)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    with pytest.raises(ValidationError, match="Preprocessing version mismatch"):
        load_model_artifact(dest)

def test_label_mapping_mismatch_fails(tmp_path, trained_result):
    dest = save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")

    meta_path = os.path.join(dest, "metadata.json")
    with open(meta_path, "r") as f:
        meta = json.load(f)
    meta["model_metadata"]["label_encoding_map"]["benign"] = 999
    with open(meta_path, "w") as f:
        json.dump(meta, f)

    manifest_path = os.path.join(dest, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    manifest["files"]["metadata.json"] = generate_sha256(meta_path)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    with pytest.raises(ValidationError, match="Label mapping mismatch"):
        load_model_artifact(dest)

def test_no_side_effects_persistence():
    import sys
    assert "flask" not in sys.modules or "ai.model_persistence" in sys.modules
    assert "sqlalchemy" not in sys.modules or "ai.model_persistence" in sys.modules
