"""Streaming CICIDS2017 GeneratedLabelledFlows preprocessing adapter.

This module deliberately owns only dataset adaptation. It does not train, scale,
activate, or alter any model or raw source file.
"""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import math
import os
import sqlite3
import tempfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from network.features import FLOW_FEATURE_ORDER
from network.parser import determine_direction

IMPLEMENTATION_VERSION = "cicids2017-adapter-1.0.0"
DIRECTION_POLICY_VERSION = "cicids2017-direction-v1"
LABEL_MAPPING_VERSION = "cicids2017-labels-v1"
LOCAL_NETWORK = ipaddress.ip_network("192.168.10.0/24")
BLANK_ROWS_EXPECTED = 288602
FEATURE_COLUMNS = list(FLOW_FEATURE_ORDER)
OUTPUT_COLUMNS = FEATURE_COLUMNS + ["label"]
PROVENANCE_COLUMNS = ["source_file", "original_row", "timestamp", "canonical_label", "feature_group_hash"]
LABEL_MAP = {
    "BENIGN": "benign",
    "DDoS": "ddos",
    "PortScan": "port_scan",
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",
    "Bot": "botnet",
}
PROTOCOL_MAP = {0: 0, 6: 1, 17: 2, 1: 3}
SUPPORTED_LABELS = tuple(LABEL_MAP.values())
KNOWN_UNSUPPORTED_LABELS = (
    "DoS slowloris", "DoS Slowhttptest", "DoS Hulk", "DoS GoldenEye",
    "Heartbleed", "Infiltration", "Web Attack – Brute Force",
    "Web Attack – XSS", "Web Attack – Sql Injection",
)
RAW_FIELDS = (
    "Source IP", "Destination IP", "Protocol", "Timestamp", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Min Packet Length", "Max Packet Length", "Average Packet Size",
    "Packet Length Mean", "Label",
)
NUMERIC_FIELDS = (
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Min Packet Length", "Max Packet Length", "Average Packet Size",
    "Packet Length Mean",
)


class PreprocessingError(RuntimeError):
    """Raised when a safety invariant prevents processing."""


def normalize_headers(headers: Iterable[str]) -> list[str]:
    return [str(value).strip() for value in headers]


def is_known_blank_row(row: Mapping[str, str]) -> bool:
    return all(str(value).strip() == "" for value in row.values())


def _finite_number(value: str, field: str) -> float:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}:unparseable") from exc
    if not math.isfinite(number):
        raise ValueError(f"{field}:non_finite")
    return number


def parse_timestamp(value: str) -> datetime:
    raw = str(value).strip()
    for fmt in ("%m/%d/%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Timestamp:invalid") from exc


def encode_protocol(raw_protocol: str) -> int:
    number = _finite_number(raw_protocol, "Protocol")
    if number != int(number) or number < 0 or number > 255:
        raise ValueError("Protocol:invalid")
    integer = int(number)
    if integer not in PROTOCOL_MAP and integer not in range(0, 256):
        raise ValueError("Protocol:invalid")
    return PROTOCOL_MAP.get(integer, 0)


def encode_direction(source_ip: str, destination_ip: str) -> int:
    try:
        source = ipaddress.ip_address(str(source_ip).strip())
        destination = ipaddress.ip_address(str(destination_ip).strip())
    except ValueError as exc:
        raise ValueError("IP:invalid") from exc
    source_local = source in LOCAL_NETWORK
    destination_local = destination in LOCAL_NETWORK
    if source_local and destination_local:
        return 1
    if source_local:
        return 2
    if destination_local:
        return 3
    return 4


def canonical_label(raw_label: str) -> str | None:
    return LABEL_MAP.get(str(raw_label).strip())


def _digest(parts: Iterable[Any]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode("utf-8", "surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def feature_group_hash(features: Mapping[str, Any], label: str) -> str:
    return _digest([features[name] for name in FEATURE_COLUMNS] + [label])


def _raw_row_hash(row: Mapping[str, str], headers: list[str]) -> str:
    return _digest([row.get(header, "") for header in headers])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject(counter: Counter[str], reason: str) -> None:
    counter[reason] += 1


def derive_row(row: Mapping[str, str]) -> tuple[dict[str, Any], str, datetime]:
    """Derive the exact project schema or raise ValueError(reason)."""
    label = canonical_label(row.get("Label", ""))
    if label is None:
        raise ValueError("Label:unsupported_or_invalid")
    timestamp = parse_timestamp(row.get("Timestamp", ""))
    duration_raw = _finite_number(row.get("Flow Duration", ""), "Flow Duration")
    if duration_raw < 0:
        raise ValueError("Flow Duration:negative")
    packets_fwd = _finite_number(row.get("Total Fwd Packets", ""), "Total Fwd Packets")
    packets_bwd = _finite_number(row.get("Total Backward Packets", ""), "Total Backward Packets")
    bytes_fwd = _finite_number(row.get("Total Length of Fwd Packets", ""), "Total Length of Fwd Packets")
    bytes_bwd = _finite_number(row.get("Total Length of Bwd Packets", ""), "Total Length of Bwd Packets")
    min_size = _finite_number(row.get("Min Packet Length", ""), "Min Packet Length")
    max_size = _finite_number(row.get("Max Packet Length", ""), "Max Packet Length")
    _finite_number(row.get("Average Packet Size", ""), "Average Packet Size")
    _finite_number(row.get("Packet Length Mean", ""), "Packet Length Mean")
    for name, number in (
        ("Total Fwd Packets", packets_fwd), ("Total Backward Packets", packets_bwd),
        ("Total Length of Fwd Packets", bytes_fwd), ("Total Length of Bwd Packets", bytes_bwd),
        ("Min Packet Length", min_size), ("Max Packet Length", max_size),
    ):
        if number < 0:
            raise ValueError(f"{name}:negative")
    packet_count = packets_fwd + packets_bwd
    byte_count = bytes_fwd + bytes_bwd
    if packet_count <= 0:
        raise ValueError("packet_count:zero")
    if min_size > max_size:
        raise ValueError("packet_size:min_gt_max")
    features = {
        "duration": duration_raw / 1_000_000.0,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "min_packet_size": min_size,
        "max_packet_size": max_size,
        "avg_packet_size": byte_count / packet_count,
        "protocol_enc": encode_protocol(row.get("Protocol", "")),
        "direction_enc": encode_direction(row.get("Source IP", ""), row.get("Destination IP", "")),
    }
    return features, label, timestamp


def _create_index(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE TABLE raw_seen (digest TEXT PRIMARY KEY, source_file TEXT NOT NULL, original_row INTEGER NOT NULL)")
    connection.execute("CREATE TABLE feature_seen (digest TEXT PRIMARY KEY)")
    connection.execute("CREATE TABLE selected (source_file TEXT, original_row INTEGER, timestamp TEXT, timestamp_key TEXT, canonical_label TEXT, feature_group_hash TEXT)")
    connection.execute("CREATE INDEX selected_order ON selected(source_file, timestamp_key, original_row)")
    connection.commit()


def _json_counts(counter: Mapping[str, int]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def process_dataset(
    input_dir: str | Path,
    output_dir: str | Path,
    *,
    expected_blank_rows: int = BLANK_ROWS_EXPECTED,
    processing_date: str | None = None,
) -> dict[str, Any]:
    """Stream all source CSVs into ML, provenance, and manifest artifacts."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    if not input_path.is_dir():
        raise PreprocessingError(f"Input directory does not exist: {input_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    csv_files = sorted(input_path.glob("*.csv"))
    if len(csv_files) != 8:
        raise PreprocessingError(f"Expected 8 source CSV files, found {len(csv_files)}")

    ml_path = output_path / "cicids2017_processed.csv"
    provenance_path = output_path / "cicids2017_provenance.csv"
    split_path = output_path / "cicids2017_split_support.csv"
    manifest_path = output_path / "cicids2017_manifest.json"
    db_fd, db_name = tempfile.mkstemp(prefix="cicids2017-dedupe-", suffix=".sqlite", dir=output_path)
    os.close(db_fd)
    connection = sqlite3.connect(db_name)
    try:
        _create_index(connection)
        physical_rows = blank_rows = valid_examined = selected = unsupported = invalid = exact_removed = 0
        raw_duplicates_by_file: Counter[str] = Counter()
        raw_duplicates_by_class: Counter[str] = Counter()
        excluded_labels: Counter[str] = Counter()
        rejection_reasons: Counter[str] = Counter()
        raw_protocols: Counter[str] = Counter()
        encoded_protocols: Counter[str] = Counter()
        directions: Counter[str] = Counter()
        before_labels: Counter[str] = Counter()
        after_labels: Counter[str] = Counter()
        feature_duplicates = 0
        feature_group_counts: Counter[str] = Counter()
        feature_group_to_rows: dict[str, list[int]] = defaultdict(list)
        stats = {name: {"min": None, "max": None} for name in FEATURE_COLUMNS}
        with ml_path.open("w", newline="", encoding="utf-8") as ml_file, \
             provenance_path.open("w", newline="", encoding="utf-8") as provenance_file, \
             split_path.open("w", newline="", encoding="utf-8") as split_file:
            ml_writer = csv.DictWriter(ml_file, fieldnames=OUTPUT_COLUMNS)
            provenance_writer = csv.DictWriter(provenance_file, fieldnames=PROVENANCE_COLUMNS)
            split_writer = csv.DictWriter(split_file, fieldnames=["source_file", "original_row", "timestamp", "canonical_label", "feature_group_hash", "temporal_block", "partition"])
            ml_writer.writeheader(); provenance_writer.writeheader(); split_writer.writeheader()
            for csv_path in csv_files:
                with csv_path.open("r", newline="", encoding="latin1") as source:
                    reader = csv.reader(source)
                    try:
                        raw_headers = next(reader)
                    except StopIteration as exc:
                        raise PreprocessingError(f"Empty source file: {csv_path.name}") from exc
                    headers = normalize_headers(raw_headers)
                    if len(headers) != len(set(headers)):
                        # Duplicate names are allowed only when not selected; identify by position.
                        selected_positions = [headers.index(name) for name in RAW_FIELDS]
                        if len(selected_positions) != len(RAW_FIELDS):
                            raise PreprocessingError(f"Required header ambiguity: {csv_path.name}")
                    required_positions = {name: headers.index(name) for name in RAW_FIELDS}
                    for original_row, values in enumerate(reader, start=2):
                        physical_rows += 1
                        if len(values) != len(headers):
                            _reject(rejection_reasons, "row:malformed_field_count"); invalid += 1; continue
                        row = {name: values[pos] for name, pos in required_positions.items()}
                        all_empty = all(str(value).strip() == "" for value in values)
                        if all_empty:
                            blank_rows += 1
                            continue
                        raw_digest = _raw_row_hash({str(i): value for i, value in enumerate(values)}, [str(i) for i in range(len(values))])
                        try:
                            features, label, timestamp = derive_row(row)
                        except ValueError as exc:
                            reason = str(exc)
                            if reason == "Label:unsupported_or_invalid":
                                raw_label = str(row.get("Label", "")).strip()
                                excluded_labels[raw_label or "<blank>"] += 1
                                unsupported += 1
                            else:
                                _reject(rejection_reasons, reason)
                                invalid += 1
                            continue
                        valid_examined += 1
                        before_labels[label] += 1
                        existing = connection.execute("SELECT source_file, original_row FROM raw_seen WHERE digest=?", (raw_digest,)).fetchone()
                        if existing:
                            exact_removed += 1
                            raw_duplicates_by_file[csv_path.name] += 1
                            raw_duplicates_by_class[label] += 1
                            continue
                        connection.execute("INSERT INTO raw_seen VALUES (?,?,?)", (raw_digest, csv_path.name, original_row))
                        group_hash = feature_group_hash(features, label)
                        if connection.execute("SELECT 1 FROM feature_seen WHERE digest=?", (group_hash,)).fetchone():
                            feature_duplicates += 1
                        else:
                            connection.execute("INSERT INTO feature_seen VALUES (?)", (group_hash,))
                        feature_group_counts[group_hash] += 1
                        if len(feature_group_to_rows[group_hash]) < 2:
                            feature_group_to_rows[group_hash].append(selected)
                        row_out = {name: features[name] for name in FEATURE_COLUMNS}
                        row_out["label"] = label
                        ml_writer.writerow(row_out)
                        provenance_writer.writerow({
                            "source_file": csv_path.name, "original_row": original_row,
                            "timestamp": timestamp.isoformat(), "canonical_label": label,
                            "feature_group_hash": group_hash,
                        })
                        connection.execute("INSERT INTO selected VALUES (?,?,?,?,?,?)", (csv_path.name, original_row, timestamp.isoformat(), timestamp.isoformat(), label, group_hash))
                        selected += 1
                        after_labels[label] += 1
                        raw_protocols[str(int(float(row["Protocol"].strip())))] += 1
                        encoded_protocols[str(features["protocol_enc"])] += 1
                        direction_name = {1:"internal",2:"outbound",3:"inbound",4:"external"}[features["direction_enc"]]
                        directions[direction_name] += 1
                        for name, value in features.items():
                            stats[name]["min"] = value if stats[name]["min"] is None else min(stats[name]["min"], value)
                            stats[name]["max"] = value if stats[name]["max"] is None else max(stats[name]["max"], value)
                        if selected % 10000 == 0:
                            connection.commit()
        connection.commit()
        if blank_rows != expected_blank_rows:
            raise PreprocessingError(f"Expected {expected_blank_rows} blank rows, observed {blank_rows}")
        # Rewrite split support from disk-backed ordered metadata. Rows are sorted by
        # scenario/file and timestamp, then divided into deterministic 5% blocks;
        # block 0..15 are training and 16..19 are testing. A feature-group hash is
        # assigned to the first partition encountered, keeping identical vectors together.
        with split_path.open("w", newline="", encoding="utf-8") as split_file:
            split_writer = csv.writer(split_file)
            split_writer.writerow(["source_file", "original_row", "timestamp", "canonical_label", "feature_group_hash", "temporal_block", "partition"])
            connection.execute("CREATE TABLE IF NOT EXISTS group_partition (digest TEXT PRIMARY KEY, partition TEXT)")
            for source_row in connection.execute("SELECT DISTINCT source_file FROM selected ORDER BY source_file"):
                source = source_row[0]
                total = connection.execute("SELECT COUNT(*) FROM selected WHERE source_file=?", (source,)).fetchone()[0]
                for index, row in enumerate(connection.execute("SELECT source_file, original_row, timestamp, canonical_label, feature_group_hash FROM selected WHERE source_file=? ORDER BY timestamp_key, original_row", (source,))):
                    block = min(19, (index * 20) // max(total, 1))
                    existing = connection.execute("SELECT partition FROM group_partition WHERE digest=?", (row[4],)).fetchone()
                    if existing is None:
                        partition = "test" if block >= 16 else "train"
                        connection.execute("INSERT INTO group_partition VALUES (?,?)", (row[4], partition))
                    else:
                        partition = existing[0]
                    split_writer.writerow((*row, block, partition))
        manifest = {
            "implementation_version": IMPLEMENTATION_VERSION,
            "source_directory": str(input_path),
            "source_zip_sha256": "7BDBEF286F8893F31C6DB12105FA097FA5C2DCC6733179037A08129D150EA27A",
            "raw_file_sha256": {},
            "direction_policy_version": DIRECTION_POLICY_VERSION,
            "label_mapping_version": LABEL_MAPPING_VERSION,
            "processing_date": processing_date or datetime.now().date().isoformat(),
            "total_physical_rows": physical_rows,
            "known_blank_rows_removed": blank_rows,
            "valid_labelled_rows_examined": physical_rows - blank_rows,
            "selected_rows": selected,
            "unsupported_label_rows_excluded": unsupported,
            "excluded_counts_by_original_label": _json_counts(excluded_labels),
            "invalid_required_field_rows_excluded": invalid,
            "rejection_counts": _json_counts(rejection_reasons),
            "raw_exact_duplicates_removed": exact_removed,
            "raw_exact_duplicates_by_file": _json_counts(raw_duplicates_by_file),
            "raw_exact_duplicates_by_class": _json_counts(raw_duplicates_by_class),
            "feature_vector_duplicate_rows_observed": feature_duplicates,
            "class_counts_before_after": {"before": _json_counts(before_labels), "after": _json_counts(after_labels)},
            "protocol_counts_raw": _json_counts(raw_protocols),
            "protocol_counts_encoded": _json_counts(encoded_protocols),
            "direction_counts": _json_counts(directions),
            "feature_min_max": stats,
            "output_sha256": {},
            "split_design": {"primary": "source-file outer group; timestamp-sorted temporal blocks; earlier 80% train/later 20% test; feature-group hashes co-located", "secondary": "stratified-random baseline, deterministic seed 42, for later comparison only"},
            "model_trained": False,
        }
        for source in csv_files:
            manifest["raw_file_sha256"][source.name] = sha256_file(source)
        for artifact in (ml_path, provenance_path, split_path):
            manifest["output_sha256"][artifact.name] = sha256_file(artifact)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return manifest
    finally:
        connection.close()
        try:
            os.remove(db_name)
        except OSError:
            pass


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/raw/cic-ids2017/generated_flows_extracted/TrafficLabelling")
    parser.add_argument("--output", default="data/processed/cicids2017")
    args = parser.parse_args()
    manifest = process_dataset(args.input, args.output)
    print(f"RAW PHYSICAL ROWS: {manifest['total_physical_rows']}")
    print(f"VALID RAW LABELLED ROWS: {manifest['valid_labelled_rows_examined']}")
    print(f"BLANK PACKAGING ROWS REMOVED: {manifest['known_blank_rows_removed']}")
    print(f"SELECTED LABELS: {', '.join(dict.fromkeys(SUPPORTED_LABELS))}")
    print(f"UNSUPPORTED LABEL ROWS EXCLUDED: {manifest['unsupported_label_rows_excluded']}")
    print(f"INVALID REQUIRED-FIELD ROWS EXCLUDED: {manifest['invalid_required_field_rows_excluded']}")
    print(f"RAW EXACT DUPLICATES REMOVED: {manifest['raw_exact_duplicates_removed']}")
    print(f"FINAL PROCESSED ROWS: {manifest['selected_rows']}")
    print(f"FINAL CLASS DISTRIBUTION: {json.dumps(manifest['class_counts_before_after']['after'], sort_keys=True)}")
    print("DURATION TRANSFORMATION: Flow Duration / 1,000,000 (microseconds to seconds)")
    print("AVG_PACKET_SIZE DECISION: byte_count / packet_count, matching live network flow semantics")
    print("PROTOCOL MAPPING: raw 0->0, 6->1, 17->2, 1->3, other valid IP protocol->0; invalid/missing rejected")
    print(f"PROTOCOL DISTRIBUTION: {json.dumps(manifest['protocol_counts_raw'], sort_keys=True)}")
    print(f"DIRECTION POLICY: {DIRECTION_POLICY_VERSION}; 192.168.10.0/24 local; 172.16.0.1 outside local set")
    print(f"DIRECTION DISTRIBUTION: {json.dumps(manifest['direction_counts'], sort_keys=True)}")
    print("PROCESSED DATASET PATH: data/processed/cicids2017/cicids2017_processed.csv")
    print("PROVENANCE PATH: data/processed/cicids2017/cicids2017_provenance.csv")
    print("MANIFEST PATH: data/processed/cicids2017/cicids2017_manifest.json")
    print(f"PROCESSED DATASET SHA-256: {manifest['output_sha256']['cicids2017_processed.csv']}")
    print("PRIMARY SPLIT DESIGN: source-file outer group; timestamp-sorted temporal blocks; feature-group hashes co-located")
    print("SECONDARY BASELINE SPLIT: stratified random, deterministic seed 42, for later comparison only")
    print("FOCUSED TESTS: run separately with pytest tests/test_cicids2017_preprocessing.py")
    print("FULL TEST SUITE: run separately with pytest")
    print("MODEL TRAINED: NO")
    print("ACTIVE MODEL CHANGED: NO")
    print("REPORT PATH: docs/CICIDS2017_PREPROCESSING_REPORT.md")


if __name__ == "__main__":
    main()
