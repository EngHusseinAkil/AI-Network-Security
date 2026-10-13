import pytest
import csv
from pathlib import Path

from network.features import FLOW_FEATURE_ORDER
from ai.data_loader import (
    load_sample_dataset,
    load_registered_dataset_sample,
    validate_dataset_columns,
    validate_dataset_rows,
    get_dataset_summary,
    FORBIDDEN_COLUMNS
)
from utils.exceptions import ValidationError
from ai.constants import PACKET_SCHEMA_VERSION, FLOW_SCHEMA_VERSION

TINY_CSV_PATH = Path("data/samples/tiny_flow_sample.csv")

def test_valid_sample_csv_loads_successfully():
    result = load_sample_dataset(TINY_CSV_PATH, schema_type="flow")

    assert "features" in result
    assert "labels" in result
    assert "schema_metadata" in result
    assert "row_count" in result
    assert "source_path" in result

    assert result["row_count"] == 8
    assert len(result["features"]) == 8
    assert len(result["labels"]) == 8

def test_feature_order_matches_flow_feature_order():
    result = load_sample_dataset(TINY_CSV_PATH, schema_type="flow")
    first_row = result["features"][0]

    # Python 3.7+ dictionaries preserve insertion order
    assert list(first_row.keys()) == FLOW_FEATURE_ORDER

def test_labels_validate_against_canonical_labels():
    result = load_sample_dataset(TINY_CSV_PATH, schema_type="flow")
    labels = set(result["labels"])
    assert labels.issubset({"benign", "ddos", "port_scan", "brute_force", "botnet", "malware", "unknown"})

def test_missing_columns_fail():
    invalid_cols = ["duration", "packet_count", "label"]
    with pytest.raises(ValidationError, match="do not match the authoritative"):
        validate_dataset_columns(invalid_cols, schema_type="flow")

def test_extra_columns_fail_in_strict_mode():
    invalid_cols = FLOW_FEATURE_ORDER + ["extra_col", "label"]
    with pytest.raises(ValidationError, match="do not match the authoritative"):
        validate_dataset_columns(invalid_cols, schema_type="flow")

def test_forbidden_payload_columns_fail():
    for forbidden in FORBIDDEN_COLUMNS:
        invalid_cols = FLOW_FEATURE_ORDER + [forbidden, "label"]
        with pytest.raises(ValidationError, match="CRITICAL PRIVACY VIOLATION"):
            validate_dataset_columns(invalid_cols, schema_type="flow")

def test_invalid_numeric_values_fail():
    invalid_rows = [{
        "duration": "1.5",
        "packet_count": "invalid",
        "byte_count": "1500",
        "min_packet_size": "64",
        "max_packet_size": "150",
        "avg_packet_size": "150.0",
        "protocol_enc": "1",
        "direction_enc": "2",
        "label": "benign"
    }]
    with pytest.raises(ValidationError, match="non-numeric"):
        validate_dataset_rows(invalid_rows, schema_type="flow")

def test_invalid_labels_fail():
    invalid_rows = [{
        "duration": "1.5",
        "packet_count": "10",
        "byte_count": "1500",
        "min_packet_size": "64",
        "max_packet_size": "150",
        "avg_packet_size": "150.0",
        "protocol_enc": "1",
        "direction_enc": "2",
        "label": "unauthorized_label"
    }]
    with pytest.raises(ValidationError, match="is not supported"):
        validate_dataset_rows(invalid_rows, schema_type="flow")

def test_source_file_is_not_modified():
    initial_mtime = TINY_CSV_PATH.stat().st_mtime
    load_sample_dataset(TINY_CSV_PATH, schema_type="flow")
    final_mtime = TINY_CSV_PATH.stat().st_mtime
    assert initial_mtime == final_mtime

def test_dataset_summary_output():
    # Use synthetic registered dataset
    result = load_registered_dataset_sample("synthetic")

    # We must format it like rows with label to use get_dataset_summary easily,
    # but the loader strips the label from features and puts it in result['labels'].
    # Let's mock rows for the summary test
    mock_rows = [{"label": "benign"}, {"label": "benign"}, {"label": "ddos"}]
    summary = get_dataset_summary(mock_rows)
    assert summary["total_rows"] == 3
    assert summary["label_distribution"]["benign"] == 2
    assert summary["label_distribution"]["ddos"] == 1



def test_missing_label_column_fails():
    invalid_cols = FLOW_FEATURE_ORDER
    with pytest.raises(ValidationError, match="must include a 'label' column"):
        validate_dataset_columns(invalid_cols, schema_type="flow")
