import pytest
import math
from copy import deepcopy

from network.features import FLOW_FEATURE_ORDER
from ai.preprocessing import (
    prepare_dataset,
    build_feature_matrix,
    build_label_vector,
    deterministic_train_test_split,
    validate_preprocessing_compatibility,
    LABEL_TO_INDEX,
    INDEX_TO_LABEL
)
from ai.constants import FLOW_SCHEMA_VERSION, PACKET_SCHEMA_VERSION, CANONICAL_LABELS
from utils.exceptions import ValidationError

@pytest.fixture
def valid_flow_bundle():
    return {
        "features": [
            {
                "duration": 1.5,
                "packet_count": 10,
                "byte_count": 1500,
                "min_packet_size": 64,
                "max_packet_size": 150,
                "avg_packet_size": 150.0,
                "protocol_enc": 1,
                "direction_enc": 2
            },
            {
                "duration": 0.5,
                "packet_count": 50,
                "byte_count": 3200,
                "min_packet_size": 64,
                "max_packet_size": 64,
                "avg_packet_size": 64.0,
                "protocol_enc": 1,
                "direction_enc": 2
            }
        ],
        "labels": ["benign", "port_scan"],
        "schema_metadata": {
            "schema_type": "flow",
            "version": FLOW_SCHEMA_VERSION
        },
        "row_count": 2,
        "source_path": "/fake/path/dataset.csv"
    }

def test_prepare_dataset_success(valid_flow_bundle):
    result = prepare_dataset(valid_flow_bundle)

    assert "X" in result
    assert "y" in result
    assert "metadata" in result

    X = result["X"]
    y = result["y"]

    assert len(X) == 2
    assert len(y) == 2
    assert len(X[0]) == len(FLOW_FEATURE_ORDER)
    assert y == [LABEL_TO_INDEX["benign"], LABEL_TO_INDEX["port_scan"]]

def test_feature_order_exactly_matches(valid_flow_bundle):
    X = build_feature_matrix(valid_flow_bundle["features"], schema_type="flow")

    # Check the first row values manually to ensure order is preserved
    # 'duration' = 1.5 is the first element
    assert X[0][0] == 1.5
    # 'packet_count' = 10 is second
    assert X[0][1] == 10.0

def test_labels_excluded_from_feature_vectors():
    features = [{"duration": 1.5, "label": "benign"}]
    with pytest.raises(ValidationError, match="Leakage detected"):
        build_feature_matrix(features, schema_type="flow")

def test_label_encoding_is_deterministic():
    # The order of CANONICAL_LABELS shouldn't change randomly
    for idx, label in enumerate(CANONICAL_LABELS):
        assert LABEL_TO_INDEX[label] == idx

def test_reverse_label_decoding_works(valid_flow_bundle):
    y = build_label_vector(valid_flow_bundle["labels"])
    decoded = [INDEX_TO_LABEL[i] for i in y]
    assert decoded == ["benign", "port_scan"]

def test_unknown_invalid_labels_fail():
    with pytest.raises(ValidationError, match="Unknown canonical label"):
        build_label_vector(["benign", "unauthorized_label"])

def test_nan_and_infinity_fails(valid_flow_bundle):
    features = deepcopy(valid_flow_bundle["features"])
    features[0]["duration"] = float('nan')
    with pytest.raises(ValidationError, match="NaN or Infinity encountered"):
        build_feature_matrix(features, schema_type="flow")

    features[0]["duration"] = float('inf')
    with pytest.raises(ValidationError, match="NaN or Infinity encountered"):
        build_feature_matrix(features, schema_type="flow")

def test_schema_mismatch_fails(valid_flow_bundle):
    bundle = deepcopy(valid_flow_bundle)
    bundle["schema_metadata"]["version"] = "99.9.9"
    with pytest.raises(ValidationError, match="Schema version mismatch"):
        validate_preprocessing_compatibility(bundle)

def test_train_test_split_preserves_alignment():
    X = [[1.0], [2.0], [3.0], [4.0], [5.0]]
    y = [1, 2, 3, 4, 5]
    X_train, X_test, y_train, y_test = deterministic_train_test_split(X, y, test_ratio=0.4, seed=42)

    # Assert alignment is preserved (each y should match X[0])
    for x_val, y_val in zip(X_train, y_train):
        assert x_val[0] == y_val
    for x_val, y_val in zip(X_test, y_test):
        assert x_val[0] == y_val

def test_train_test_split_deterministic():
    X = [[1.0], [2.0], [3.0], [4.0], [5.0]]
    y = [1, 2, 3, 4, 5]

    X_train1, X_test1, y_train1, y_test1 = deterministic_train_test_split(X, y, test_ratio=0.4, seed=99)
    X_train2, X_test2, y_train2, y_test2 = deterministic_train_test_split(X, y, test_ratio=0.4, seed=99)

    assert X_train1 == X_train2
    assert y_train1 == y_train2

def test_invalid_split_ratios_fail():
    X = [[1.0], [2.0]]
    y = [1, 2]
    with pytest.raises(ValidationError):
        deterministic_train_test_split(X, y, test_ratio=0.0)
    with pytest.raises(ValidationError):
        deterministic_train_test_split(X, y, test_ratio=1.0)
    with pytest.raises(ValidationError):
        deterministic_train_test_split(X, y, test_ratio=1.5)

def test_input_data_remains_unchanged(valid_flow_bundle):
    original_bundle = deepcopy(valid_flow_bundle)
    prepare_dataset(valid_flow_bundle)
    assert valid_flow_bundle == original_bundle

def test_metadata_is_deterministic(valid_flow_bundle):
    result = prepare_dataset(valid_flow_bundle)
    meta = result["metadata"]
    assert meta["scaling_strategy"] == "none_applied"
    assert meta["ordered_feature_names"] == FLOW_FEATURE_ORDER
    assert meta["row_count"] == 2
    assert "schema_version" in meta
