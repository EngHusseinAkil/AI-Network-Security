"""
AI Model Persistence.

Handles secure serialization, integrity validation, and structured loading
of fitted AI models and their exact evaluation metadata.
"""

import os
import json
import hashlib
import joblib
import time
import shutil
from typing import Dict, Any, Optional

from sklearn.utils.validation import check_is_fitted

from utils.exceptions import ValidationError
from ai.constants import FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from network.features import FLOW_FEATURE_ORDER


def generate_sha256(filepath: str) -> str:
    """Generates a SHA-256 hash for a given file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def save_model_artifact(
    training_result: Dict[str, Any],
    evaluation_result: Optional[Dict[str, Any]],
    destination_dir: str,
    model_version: str
) -> str:
    """
    Saves a fitted model to disk atomically with metadata, evaluation, and manifest.
    Does not overwrite existing versions.
    """
    if not model_version or not isinstance(model_version, str):
        raise ValidationError("model_version must be a valid string.")

    estimator = training_result.get("estimator")
    if estimator is None:
        raise ValidationError("Cannot save: training result contains no estimator.")

    try:
        check_is_fitted(estimator)
    except Exception as e:
        raise ValidationError("Cannot save: estimator is not fitted.") from e

    model_dir = os.path.join(destination_dir, f"model_{model_version}")

    if os.path.exists(model_dir):
        raise ValidationError(f"Model version '{model_version}' already exists at {model_dir}. Overwrites are forbidden.")

    # We will write to a temporary directory first to guarantee atomicity
    temp_dir = f"{model_dir}_tmp_{int(time.time())}"
    os.makedirs(temp_dir, exist_ok=False)

    try:
        # 1. Save Estimator
        estimator_path = os.path.join(temp_dir, "estimator.joblib")
        joblib.dump(estimator, estimator_path)

        # 2. Save Metadata
        # We augment the metadata with our own schema format
        metadata = training_result.get("model_metadata", {})
        metadata_export = {
            "artifact_format_version": "1.0",
            "model_version": model_version,
            "creation_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "schema_metadata": training_result.get("schema_metadata", {}),
            "model_metadata": metadata,
            "security_disclaimer": "Do NOT load pickle/joblib artifacts from untrusted sources. This allows remote code execution."
        }
        metadata_path = os.path.join(temp_dir, "metadata.json")
        with open(metadata_path, "w") as f:
            json.dump(metadata_export, f, indent=4)

        # 3. Save Evaluation (Optional)
        eval_path = None
        if evaluation_result:
            # Prevent estimator passing through evaluation accidentally
            if "estimator" in evaluation_result:
                raise ValidationError("Evaluation result must not contain raw estimators.")

            eval_path = os.path.join(temp_dir, "evaluation.json")
            with open(eval_path, "w") as f:
                json.dump(evaluation_result, f, indent=4)

        # 4. Generate Manifest
        manifest = {
            "artifact_format_version": "1.0",
            "model_version": model_version,
            "files": {
                "estimator.joblib": generate_sha256(estimator_path),
                "metadata.json": generate_sha256(metadata_path)
            }
        }
        if eval_path:
            manifest["files"]["evaluation.json"] = generate_sha256(eval_path)

        manifest_path = os.path.join(temp_dir, "manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)

        # 5. Atomic Rename (If rename fails, we just leave the tmp dir for debug or clean it)
        os.rename(temp_dir, model_dir)
        return model_dir

    except Exception as e:
        # Cleanup partial state on any failure
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise ValidationError(f"Model persistence failed: {str(e)}") from e


def load_model_artifact(model_dir: str) -> Dict[str, Any]:
    """
    Loads and rigorously validates a saved model artifact.
    Prevents execution if compatibility or integrity rules fail.
    """
    if not os.path.exists(model_dir):
        raise ValidationError(f"Model directory does not exist: {model_dir}")

    manifest_path = os.path.join(model_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        raise ValidationError("Missing manifest.json. Artifact may be corrupted or untrusted.")

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    expected_files = manifest.get("files", {})

    # 1. Integrity Validation (Hashes)
    for filename, expected_hash in expected_files.items():
        filepath = os.path.join(model_dir, filename)
        if not os.path.exists(filepath):
            raise ValidationError(f"Missing required file from manifest: {filename}")

        actual_hash = generate_sha256(filepath)
        if actual_hash != expected_hash:
            raise ValidationError(f"Integrity check failed for {filename}. Artifact is corrupted or altered.")

    # 2. Load Metadata
    metadata_path = os.path.join(model_dir, "metadata.json")
    with open(metadata_path, "r") as f:
        metadata_export = json.load(f)

    # 3. Compatibility Validation
    schema_meta = metadata_export.get("schema_metadata", {})
    model_meta = metadata_export.get("model_metadata", {})

    if schema_meta.get("schema_type") != "flow":
        raise ValidationError("Incompatible schema type. Expected 'flow'.")

    if schema_meta.get("schema_version") != FLOW_SCHEMA_VERSION:
        raise ValidationError(f"Schema version mismatch. Expected {FLOW_SCHEMA_VERSION}, got {schema_meta.get('schema_version')}")

    if schema_meta.get("preprocessing_version") != "1.0.0":
        raise ValidationError("Preprocessing version mismatch. Expected 1.0.0.")

    if model_meta.get("ordered_feature_names") != FLOW_FEATURE_ORDER:
        raise ValidationError("Feature ordering mismatch. Artifact is incompatible with current Network Engine.")

    # Ensure label definitions haven't drifted silently
    loaded_mapping = model_meta.get("label_encoding_map", {})
    expected_mapping = {label: idx for idx, label in enumerate(CANONICAL_LABELS)}
    if loaded_mapping != expected_mapping:
        raise ValidationError("Label mapping mismatch. Canonical labels have drifted since this model was built.")

    # 4. Load Evaluation if present
    evaluation_result = None
    if "evaluation.json" in expected_files:
        eval_path = os.path.join(model_dir, "evaluation.json")
        with open(eval_path, "r") as f:
            evaluation_result = json.load(f)

    # 5. Load Estimator (WARNING: Joblib can execute code. Only load from trusted paths.)
    estimator_path = os.path.join(model_dir, "estimator.joblib")
    try:
        estimator = joblib.load(estimator_path)
    except Exception as e:
        raise ValidationError(f"Failed to deserialize estimator: {str(e)}") from e

    # 6. Final Estimator State Validation
    try:
        check_is_fitted(estimator)
    except Exception as e:
        raise ValidationError("Deserialized estimator is not fitted.") from e

    if getattr(estimator, "n_features_in_", None) != len(FLOW_FEATURE_ORDER):
        raise ValidationError("Deserialized estimator feature count does not match current FLOW_FEATURE_ORDER.")

    return {
        "estimator": estimator,
        "metadata": metadata_export,
        "evaluation": evaluation_result
    }
