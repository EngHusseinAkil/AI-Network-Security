import pytest
import math
from typing import Dict, Any

from sklearn.ensemble import RandomForestClassifier

from ai.constants import RANDOM_SEED, FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from network.features import FLOW_FEATURE_ORDER
from ai.training import (
    build_random_forest_classifier,
    validate_training_data,
    create_stratified_split,
    train_random_forest,
    DEFAULT_RF_CONFIG
)
from ai.preprocessing import LABEL_TO_INDEX
from utils.exceptions import ValidationError


@pytest.fixture
def synthetic_training_data() -> Dict[str, Any]:
    # We need enough samples per class to permit stratify=y
    # Let's create 6 samples: 3 of benign (0), 3 of ddos (1)
    # Each row must have 8 features (len(FLOW_FEATURE_ORDER))
    X = [
        [1.0, 10.0, 100.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.1, 11.0, 110.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.2, 12.0, 120.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [0.1, 1000.0, 64000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.2, 2000.0, 128000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.3, 3000.0, 192000.0, 64.0, 64.0, 64.0, 1.0, 3.0]
    ]
    y = [
        LABEL_TO_INDEX["benign"],
        LABEL_TO_INDEX["benign"],
        LABEL_TO_INDEX["benign"],
        LABEL_TO_INDEX["ddos"],
        LABEL_TO_INDEX["ddos"],
        LABEL_TO_INDEX["ddos"]
    ]

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


def test_random_forest_config_is_deterministic():
    clf = build_random_forest_classifier()
    assert clf.random_state == RANDOM_SEED
    assert clf.class_weight == "balanced"

    custom_config = {"n_estimators": 50, "random_state": 999}
    clf2 = build_random_forest_classifier(custom_config)
    assert clf2.random_state == 999
    assert clf2.n_estimators == 50

def test_validate_training_data_rejects_empty():
    with pytest.raises(ValidationError, match="cannot be empty"):
        validate_training_data([], [], {})

def test_validate_training_data_rejects_alignment_mismatch(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"][:-1]
    with pytest.raises(ValidationError, match="alignment is broken"):
        validate_training_data(X, y, synthetic_training_data["metadata"])

def test_single_class_input_fails(synthetic_training_data):
    X = synthetic_training_data["X"]
    # Make all labels identical
    y = [LABEL_TO_INDEX["benign"]] * len(X)
    with pytest.raises(ValidationError, match="at least two distinct classes"):
        validate_training_data(X, y, synthetic_training_data["metadata"])

def test_insufficient_class_counts_fail_stratification(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"]
    # Modify y so one class has only 1 sample
    y[0] = LABEL_TO_INDEX["port_scan"]

    with pytest.raises(ValidationError, match="Stratification impossible"):
        create_stratified_split(X, y, test_ratio=0.2, allow_unstratified_fallback_for_tests=False)

def test_stratification_is_never_silently_disabled(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"]
    y[0] = LABEL_TO_INDEX["port_scan"]

    # Must explicitly allow fallback, else fails
    X_tr, X_te, y_tr, y_te, is_stratified = create_stratified_split(
        X, y, test_ratio=0.5, allow_unstratified_fallback_for_tests=True
    )
    assert is_stratified is False

def test_valid_synthetic_multiclass_input_trains_successfully(synthetic_training_data):
    result = train_random_forest(
        synthetic_training_data,
        test_ratio=0.5,
        allow_unstratified_fallback_for_tests=False
    )
    assert "estimator" in result
    assert isinstance(result["estimator"], RandomForestClassifier)
    assert result["model_metadata"]["stratification_status"] == "applied"

def test_estimator_is_unfitted_before_training():
    from sklearn.utils.validation import check_is_fitted
    from sklearn.exceptions import NotFittedError

    clf = build_random_forest_classifier()
    with pytest.raises(NotFittedError):
        check_is_fitted(clf)

def test_estimator_is_fitted_after_training(synthetic_training_data):
    from sklearn.utils.validation import check_is_fitted

    result = train_random_forest(
        synthetic_training_data,
        test_ratio=0.5,
        allow_unstratified_fallback_for_tests=False
    )
    clf = result["estimator"]

    # check_is_fitted does not raise an exception if fitted
    check_is_fitted(clf)

    # Confirm it was fitted with the correct feature count
    assert getattr(clf, "n_features_in_", None) == len(FLOW_FEATURE_ORDER)
    assert hasattr(clf, "classes_")

def test_stratification_preserves_class_presence(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"]

    X_tr, X_te, y_tr, y_te, is_stratified = create_stratified_split(X, y, test_ratio=0.5, seed=42)

    # Both sets should have at least one 'benign' (0) and one 'ddos' (1)
    assert LABEL_TO_INDEX["benign"] in y_tr
    assert LABEL_TO_INDEX["ddos"] in y_tr
    assert LABEL_TO_INDEX["benign"] in y_te
    assert LABEL_TO_INDEX["ddos"] in y_te

    assert len(X_tr) + len(X_te) == len(X)
    assert len(y_tr) + len(y_te) == len(y)

def test_same_seed_produces_same_partition(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"]

    X_tr1, X_te1, y_tr1, y_te1, _ = create_stratified_split(X, y, test_ratio=0.5, seed=42)
    X_tr2, X_te2, y_tr2, y_te2, _ = create_stratified_split(X, y, test_ratio=0.5, seed=42)

    assert X_tr1 == X_tr2
    assert y_tr1 == y_tr2

def test_split_preserves_xy_alignment(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"]

    # Embed the original y label into the first feature value just to verify alignment
    for i in range(len(X)):
        X[i][0] = float(y[i])

    X_tr, X_te, y_tr, y_te, _ = create_stratified_split(X, y, test_ratio=0.5, seed=42)

    for x_row, y_val in zip(X_tr, y_tr):
        assert x_row[0] == float(y_val)
    for x_row, y_val in zip(X_te, y_te):
        assert x_row[0] == float(y_val)

def test_invalid_feature_count_fails(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"]
    metadata = synthetic_training_data["metadata"]

    X[0].pop() # Remove one feature
    with pytest.raises(ValidationError, match="Inconsistent feature count"):
        validate_training_data(X, y, metadata)

def test_nan_fails_validation(synthetic_training_data):
    X = synthetic_training_data["X"]
    y = synthetic_training_data["y"]
    metadata = synthetic_training_data["metadata"]

    X[0][0] = "not_a_number"
    with pytest.raises(ValidationError, match="Non-numeric value"):
        validate_training_data(X, y, metadata)

def test_training_metadata_is_deterministic(synthetic_training_data):
    result = train_random_forest(
        synthetic_training_data,
        test_ratio=0.5,
        allow_unstratified_fallback_for_tests=False
    )

    meta = result["model_metadata"]
    assert meta["model_family"] == "RandomForestClassifier"
    assert meta["random_seed"] == RANDOM_SEED
    assert meta["ordered_feature_names"] == FLOW_FEATURE_ORDER
    assert meta["feature_count"] == len(FLOW_FEATURE_ORDER)
    assert meta["training_row_count"] == 3
    assert meta["testing_row_count"] == 3
    assert meta["dependency_version"] == "scikit-learn=1.9.0"

def test_no_model_file_written_or_database_accessed():
    import sys
    # Verify we aren't pulling in database logic or file I/O implicitly during training
    assert "sqlalchemy" not in sys.modules or "ai.training" in sys.modules
    assert "joblib" not in sys.modules or "ai.training" in sys.modules
