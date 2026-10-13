"""
Deterministic AI Preprocessing Layer.

Transforms validated Dataset Loader structures into deterministic, ML-ready numerical
matrices. Strictly enforces schema ordering, safety checks, and deterministic label encoding.
No model training or automated scaling is performed here, preserving strict pipeline separation.
"""

import math
import random
from typing import Dict, List, Any, Tuple
from copy import deepcopy

from ai.constants import (
    CANONICAL_LABELS,
    PACKET_SCHEMA_VERSION,
    FLOW_SCHEMA_VERSION,
    RANDOM_SEED
)
from network.features import FLOW_FEATURE_ORDER, PACKET_FEATURE_ORDER
from utils.exceptions import ValidationError

# Deterministic Label Encoding
# We derive integer mappings exactly from the ordered CANONICAL_LABELS tuple
# to guarantee they never change across process restarts.
LABEL_TO_INDEX: Dict[str, int] = {label: idx for idx, label in enumerate(CANONICAL_LABELS)}
INDEX_TO_LABEL: Dict[int, str] = {idx: label for idx, label in enumerate(CANONICAL_LABELS)}


def _resolve_schema_identity(schema_metadata: Dict[str, Any]) -> Tuple[str, str]:
    """Accept current authoritative metadata and the legacy internal test shape."""
    schema_type = schema_metadata.get("schema_type")
    if not schema_type:
        schema_name = schema_metadata.get("schema_name")
        schema_type = {
            "flow_features": "flow",
            "packet_features": "packet",
        }.get(schema_name)
    version = schema_metadata.get("version") or schema_metadata.get("schema_version")
    if schema_type not in {"flow", "packet"}:
        raise ValidationError("Dataset schema type is missing or unsupported.")
    return schema_type, version


def validate_preprocessing_compatibility(dataset_bundle: Dict[str, Any]) -> None:
    """
    Ensures the loaded dataset bundle is structurally sound and compatible with
    the current preprocessing engine.
    """
    required_keys = {"features", "labels", "schema_metadata", "row_count", "source_path"}
    if not required_keys.issubset(dataset_bundle.keys()):
        raise ValidationError("Dataset bundle is missing required logical structures.")

    if dataset_bundle["row_count"] != len(dataset_bundle["features"]) or \
       dataset_bundle["row_count"] != len(dataset_bundle["labels"]):
        raise ValidationError("Dataset bundle row counts do not match feature/label lengths.")

    schema_metadata = dataset_bundle["schema_metadata"]
    schema_type, version = _resolve_schema_identity(schema_metadata)

    if schema_type == "flow" and version != FLOW_SCHEMA_VERSION:
        raise ValidationError(f"Schema version mismatch. Expected Flow {FLOW_SCHEMA_VERSION}, got {version}.")
    if schema_type == "packet" and version != PACKET_SCHEMA_VERSION:
        raise ValidationError(f"Schema version mismatch. Expected Packet {PACKET_SCHEMA_VERSION}, got {version}.")


def build_label_vector(labels: List[str]) -> List[int]:
    """
    Transforms canonical string labels into deterministic integer encodings.
    """
    vector = []
    for lbl in labels:
        lbl_lower = lbl.strip().lower()
        if lbl_lower not in LABEL_TO_INDEX:
            raise ValidationError(f"Unknown canonical label encountered during encoding: {lbl_lower}")
        vector.append(LABEL_TO_INDEX[lbl_lower])
    return vector


def build_feature_matrix(features: List[Dict[str, Any]], schema_type: str = "flow") -> List[List[float]]:
    """
    Transforms list of feature dictionaries into a deterministic numerical 2D matrix (list of lists).
    Asserts exact column ordering matching the authoritative network runtime features.
    """
    if schema_type == "flow":
        expected_order = FLOW_FEATURE_ORDER
    elif schema_type == "packet":
        expected_order = PACKET_FEATURE_ORDER
    else:
        raise ValidationError(f"Unknown schema type: {schema_type}")

    matrix = []
    for row_dict in features:
        # Leakage prevention: aggressively ensure 'label' is not in the feature dict
        if "label" in row_dict:
            raise ValidationError("Leakage detected: 'label' found in feature dictionary.")

        # Ensure exact match of keys
        if set(row_dict.keys()) != set(expected_order):
            raise ValidationError("Feature dictionary keys do not match expected schema order exactly.")

        row_vector = []
        for feature_name in expected_order:
            val = row_dict[feature_name]

            # Numeric conversion & safety checks
            try:
                float_val = float(val)
            except (ValueError, TypeError):
                raise ValidationError(f"Non-numeric value encountered for feature '{feature_name}'.")

            if math.isnan(float_val) or math.isinf(float_val):
                raise ValidationError(f"NaN or Infinity encountered for feature '{feature_name}'.")

            row_vector.append(float_val)

        matrix.append(row_vector)

    return matrix


def deterministic_train_test_split(
    X: List[List[float]],
    y: List[int],
    test_ratio: float = 0.2,
    seed: int = RANDOM_SEED
) -> Tuple[List[List[float]], List[List[float]], List[int], List[int]]:
    """
    Performs a deterministic, reproducible train/test split.
    Does not use sklearn. Ensures strict alignment of X and y.
    Returns (X_train, X_test, y_train, y_test).
    """
    if not (0.0 < test_ratio < 1.0):
        raise ValidationError("Test ratio must be strictly between 0.0 and 1.0")

    if len(X) == 0 or len(X) != len(y):
        raise ValidationError("X and y must be non-empty and equal in length.")

    # Zip together to maintain alignment during shuffle
    combined = list(zip(X, y))

    # Deterministic shuffle
    rng = random.Random(seed)
    rng.shuffle(combined)

    split_index = int(len(combined) * (1 - test_ratio))

    # Edge case: test ratio is very small and rounds to 0 test samples, or 0 train samples
    if split_index == 0 or split_index == len(combined):
        raise ValidationError("Dataset is too small to split with the given test ratio.")

    train = combined[:split_index]
    test = combined[split_index:]

    X_train = [item[0] for item in train]
    y_train = [item[1] for item in train]
    X_test = [item[0] for item in test]
    y_test = [item[1] for item in test]

    return X_train, X_test, y_train, y_test


def prepare_dataset(dataset_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Orchestrates the deterministic transformation of a dataset bundle into a
    preprocessed structure with comprehensive metadata and safety boundaries.
    """
    validate_preprocessing_compatibility(dataset_bundle)

    schema_type, schema_version = _resolve_schema_identity(
        dataset_bundle["schema_metadata"]
    )

    if schema_type == "flow":
        feature_names = FLOW_FEATURE_ORDER
    else:
        feature_names = PACKET_FEATURE_ORDER

    # Perform strict deterministic transformations
    X = build_feature_matrix(dataset_bundle["features"], schema_type=schema_type)
    y = build_label_vector(dataset_bundle["labels"])

    # Bundle preprocessed data and metadata securely
    return {
        "X": X,
        "y": y,
        "metadata": {
            "schema_type": schema_type,
            "schema_version": schema_version,
            "preprocessing_version": "1.0.0",
            "ordered_feature_names": feature_names,
            "feature_count": len(feature_names),
            "row_count": len(X),
            "label_encoding_map": deepcopy(LABEL_TO_INDEX),
            "scaling_strategy": "none_applied",
            "random_seed_used": RANDOM_SEED,
            "notes": "No automated scaling applied. Random Forest ready."
        }
    }
