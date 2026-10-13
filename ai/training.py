"""
AI Random Forest Baseline Training Infrastructure.

Establishes a professional, reproducible training boundary strictly separated from
live network traffic and dataset parsing. Uses scikit-learn for statistically
sound stratified splitting and deterministic model fitting.
"""

from collections import Counter
from typing import Dict, List, Any, Tuple, Optional
from copy import deepcopy

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from ai.constants import RANDOM_SEED, FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from utils.exceptions import ValidationError


DEFAULT_RF_CONFIG = {
    "n_estimators": 100,
    "max_depth": 20,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "class_weight": "balanced", # Required for imbalanced cyber datasets
    "n_jobs": -1,               # Utilize available CPU cores safely
    "random_state": RANDOM_SEED
}


def build_random_forest_classifier(config: Optional[Dict[str, Any]] = None) -> RandomForestClassifier:
    """
    Constructs an unfitted RandomForestClassifier with deterministic, conservative defaults.
    """
    rf_params = deepcopy(DEFAULT_RF_CONFIG)
    if config:
        rf_params.update(config)

    # Enforce global seed if not provided
    if "random_state" not in rf_params or rf_params["random_state"] is None:
        rf_params["random_state"] = RANDOM_SEED

    return RandomForestClassifier(**rf_params)


def validate_training_data(X: List[List[float]], y: List[int], metadata: Dict[str, Any]) -> None:
    """
    Asserts the prepared dataset is structurally sound and strictly numeric.
    Prevents malformed data from reaching the model fitting stage.
    """
    if not X or not y:
        raise ValidationError("Feature matrix X and label vector y cannot be empty.")

    if len(X) != len(y):
        raise ValidationError("X and y length alignment is broken.")

    # Ensure at least two classes exist for classification
    unique_classes = set(y)
    if len(unique_classes) < 2:
        raise ValidationError("Dataset must contain at least two distinct classes for classification.")

    # Validate canonical labels
    max_valid_label_idx = len(CANONICAL_LABELS) - 1
    for label_idx in unique_classes:
        if not (0 <= label_idx <= max_valid_label_idx):
            raise ValidationError(f"Encountered unknown encoded label index: {label_idx}")

    # Validate schema
    if metadata.get("schema_type") == "flow" and metadata.get("schema_version") != FLOW_SCHEMA_VERSION:
        raise ValidationError("Training data schema version is incompatible with current trainer.")

    # Verify strict numeric structure and consistent feature count
    expected_features = metadata.get("feature_count", 0)
    for row in X:
        if len(row) != expected_features:
            raise ValidationError("Inconsistent feature count detected in X matrix.")
        for val in row:
            if not isinstance(val, (int, float)):
                raise ValidationError("Non-numeric value detected in X matrix.")


def create_stratified_split(
    X: List[List[float]],
    y: List[int],
    test_ratio: float = 0.2,
    seed: int = RANDOM_SEED,
    allow_unstratified_fallback_for_tests: bool = False
) -> Tuple[List[List[float]], List[List[float]], List[int], List[int], bool]:
    """
    Splits the dataset deterministically using scikit-learn.
    Strictly enforces stratification by default to prevent catastrophic class imbalance.
    Returns (X_train, X_test, y_train, y_test, is_stratified).
    """
    if not (0.0 < test_ratio < 1.0):
        raise ValidationError("Test ratio must be strictly between 0.0 and 1.0")

    class_counts = Counter(y)

    # For stratification to be mathematically possible in scikit-learn,
    # the least populated class in y must have at least 2 members.
    stratification_possible = all(count >= 2 for count in class_counts.values())

    if stratification_possible:
        # Standard robust stratified split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_ratio, random_state=seed, stratify=y
        )
        return X_train, X_test, y_train, y_test, True
    else:
        if allow_unstratified_fallback_for_tests:
            # Dangerous in production, strictly limited to synthetic unit tests
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_ratio, random_state=seed, stratify=None
            )
            return X_train, X_test, y_train, y_test, False
        else:
            raise ValidationError(
                "Stratification impossible: dataset contains a class with fewer than 2 samples. "
                "Provide a larger, representative dataset or enable the testing fallback."
            )


def train_random_forest(
    prepared_data: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    test_ratio: float = 0.2,
    allow_unstratified_fallback_for_tests: bool = False
) -> Dict[str, Any]:
    """
    Executes the training boundary.
    Accepts preprocessed data, splits it, fits a Random Forest, and generates metadata.
    Does NOT modify the Network Engine, parse CSVs, or save model artifacts to disk.
    """
    # 1. Extract and Validate
    X = prepared_data.get("X", [])
    y = prepared_data.get("y", [])
    metadata = prepared_data.get("metadata", {})

    validate_training_data(X, y, metadata)

    # 2. Strict Stratified Split
    X_train, X_test, y_train, y_test, is_stratified = create_stratified_split(
        X, y, test_ratio=test_ratio, seed=RANDOM_SEED,
        allow_unstratified_fallback_for_tests=allow_unstratified_fallback_for_tests
    )

    # 3. Model Configuration and Fitting
    clf = build_random_forest_classifier(config)
    clf.fit(X_train, y_train)

    # 4. Generate Training Metadata
    train_dist = dict(Counter(y_train))
    test_dist = dict(Counter(y_test))

    # Safe Partitioning References (avoiding returning raw X/y copies to prevent memory bloat)
    # The caller can recreate the split deterministically using the seed, or we provide shape metrics.

    training_result = {
        "estimator": clf,
        "schema_metadata": {
            "schema_type": metadata.get("schema_type"),
            "schema_version": metadata.get("schema_version"),
            "preprocessing_version": metadata.get("preprocessing_version")
        },
        "partition_data": {
            "X_test": X_test,
            "y_test": y_test
        },
        "model_metadata": {
            "model_family": "RandomForestClassifier",
            "model_configuration": clf.get_params(),
            "random_seed": RANDOM_SEED,
            "ordered_feature_names": metadata.get("ordered_feature_names"),
            "feature_count": metadata.get("feature_count"),
            "label_encoding_map": metadata.get("label_encoding_map"),
            "training_row_count": len(X_train),
            "testing_row_count": len(X_test),
            "class_distribution_train": train_dist,
            "class_distribution_test": test_dist,
            "stratification_status": "applied" if is_stratified else "disabled_testing_fallback",
            "dependency_version": "scikit-learn=1.9.0", # hardcoded tracking for model provenance
            "disclaimer": "Synthetic test datasets used for validation do NOT represent actual threat-detection performance."
        }
    }

    return training_result
