import csv
import json
from pathlib import Path

import pytest

from ai.cicids2017_preprocessing import (
    FEATURE_COLUMNS,
    LABEL_MAP,
    canonical_label,
    derive_row,
    encode_direction,
    encode_protocol,
    feature_group_hash,
    is_known_blank_row,
    normalize_headers,
    process_dataset,
)


def row(**overrides):
    value = {
        "Source IP": "192.168.10.3",
        "Destination IP": "8.8.8.8",
        "Protocol": "6",
        "Timestamp": "7/7/2017 3:30",
        "Flow Duration": "1000000",
        "Total Fwd Packets": "2",
        "Total Backward Packets": "1",
        "Total Length of Fwd Packets": "100",
        "Total Length of Bwd Packets": "50",
        "Min Packet Length": "10",
        "Max Packet Length": "100",
        "Average Packet Size": "999",
        "Packet Length Mean": "20",
        "Label": "BENIGN",
    }
    value.update(overrides)
    return value


def test_header_normalization_and_blank_detection():
    assert normalize_headers([" Flow Duration ", "Label"]) == ["Flow Duration", "Label"]
    assert is_known_blank_row({"a": "", "b": "  "})
    assert not is_known_blank_row({"a": "", "b": "x"})


def test_feature_derivation_uses_live_average_semantics():
    features, label, timestamp = derive_row(row())
    assert features["duration"] == 1.0
    assert features["packet_count"] == 3
    assert features["byte_count"] == 150
    assert features["avg_packet_size"] == 50.0
    assert label == "benign"
    assert timestamp.year == 2017


@pytest.mark.parametrize(("raw", "expected"), [("0", 0), ("6", 1), ("17", 2), ("1", 3), ("99", 0)])
def test_protocol_encoding(raw, expected):
    assert encode_protocol(raw) == expected


def test_invalid_protocol_is_rejected():
    with pytest.raises(ValueError, match="Protocol"):
        encode_protocol("")


@pytest.mark.parametrize(
    ("source", "destination", "expected"),
    [
        ("192.168.10.3", "192.168.10.50", 1),
        ("192.168.10.3", "8.8.8.8", 2),
        ("8.8.8.8", "192.168.10.3", 3),
        ("8.8.8.8", "1.1.1.1", 4),
        ("172.16.0.1", "192.168.10.3", 3),
    ],
)
def test_direction_policy_and_gateway_boundary(source, destination, expected):
    assert encode_direction(source, destination) == expected


@pytest.mark.parametrize(
    "overrides",
    [
        {"Flow Duration": "-1"},
        {"Min Packet Length": "101", "Max Packet Length": "100"},
        {"Total Fwd Packets": "nan"},
        {"Total Length of Bwd Packets": "inf"},
        {"Source IP": ""},
        {"Label": ""},
    ],
)
def test_required_invalid_values_rejected(overrides):
    with pytest.raises(ValueError):
        derive_row(row(**overrides))


def test_unused_infinity_does_not_remove_complete_row():
    values = row()
    values["Unused Flow Bytes/s"] = "inf"
    features, _, _ = derive_row(values)
    assert features["byte_count"] == 150


@pytest.mark.parametrize(("raw", "expected"), [("BENIGN", "benign"), ("FTP-Patator", "brute_force")])
def test_label_mapping(raw, expected):
    assert canonical_label(raw) == expected


def test_unsupported_label_exclusion():
    assert canonical_label("DoS Hulk") is None
    assert set(LABEL_MAP) >= {"BENIGN", "DDoS", "PortScan", "Bot"}


def test_feature_group_hash_is_deterministic():
    features, label, _ = derive_row(row())
    assert feature_group_hash(features, label) == feature_group_hash(features, label)
    assert len(feature_group_hash(features, label)) == 64


def test_process_dataset_removes_only_expected_blank_rows_and_is_reproducible(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    headers = list(row().keys())
    headers += ["Unused Flow Bytes/s"]
    for index in range(8):
        path = source / f"scenario-{index}.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            writer.writerow({**row(), "Unused Flow Bytes/s": "inf"})
            writer.writerow({key: "" for key in headers})
    manifest = process_dataset(source, output, expected_blank_rows=8, processing_date="2026-08-21")
    assert manifest["known_blank_rows_removed"] == 8
    assert manifest["selected_rows"] == 1
    assert manifest["raw_exact_duplicates_removed"] == 7
    assert json.loads((output / "cicids2017_manifest.json").read_text())["model_trained"] is False
    with (output / "cicids2017_processed.csv").open(newline="", encoding="utf-8") as handle:
        assert next(csv.reader(handle)) == FEATURE_COLUMNS + ["label"]

