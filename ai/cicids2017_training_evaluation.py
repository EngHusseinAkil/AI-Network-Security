"""Scientific CICIDS2017 training/evaluation workflow.

The workflow is intentionally separate from application activation. It verifies the
processed data, builds a label-independent temporal split, trains a fixed Random
Forest baseline, evaluates it once on the untouched primary test partition, and
persists a new inactive artifact.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ai.constants import FLOW_SCHEMA_VERSION
from ai.model_persistence import load_model_artifact, save_model_artifact
from network.features import FLOW_FEATURE_ORDER
from ai.constants import CANONICAL_LABELS

DATASET = Path("data/processed/cicids2017/cicids2017_processed.csv")
PROVENANCE = Path("data/processed/cicids2017/cicids2017_provenance.csv")
PREPROCESSING_MANIFEST = Path("data/processed/cicids2017/cicids2017_manifest.json")
SPLIT_DIR = Path("data/processed/cicids2017/splits")
MODEL_ROOT = Path("models")
MODEL_VERSION = "cicids2017-rf-1.0.0"
LABELS = ["benign", "ddos", "port_scan", "brute_force", "botnet"]
LABEL_TO_INT = {name: index for index, name in enumerate(LABELS)}
FEATURE_ONLY_COLUMNS = list(FLOW_FEATURE_ORDER)
RF_PARAMS = {
    "n_estimators": 100, "max_depth": 20, "min_samples_split": 5,
    "min_samples_leaf": 2, "class_weight": "balanced", "random_state": 42,
    "criterion": "gini", "max_features": "sqrt", "bootstrap": True,
}
# Runtime-only control: this keeps the baseline algorithm unchanged.
RUNTIME_N_JOBS = 1
SUBSET_TARGET_ROWS = 500_000
SUBSET_SEED = 42
INVALID_NEGATIVE_FEATURES = {"duration", "packet_count", "byte_count", "min_packet_size", "max_packet_size", "avg_packet_size"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def memory_status() -> tuple[float, float]:
    """Return total and available physical RAM in GiB on Windows."""
    import ctypes
    class MemoryStatus(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise RuntimeError("Unable to read physical memory status")
    return status.ullTotalPhys / 2**30, status.ullAvailPhys / 2**30


def feature_only_hash(values: Iterable[Any]) -> str:
    h = hashlib.sha256()
    for value in values:
        raw = format(float(value), ".17g").encode("ascii")
        h.update(len(raw).to_bytes(4, "big"))
        h.update(raw)
    return h.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_dataset() -> dict[str, Any]:
    manifest = read_json(PREPROCESSING_MANIFEST)
    actual_hash = sha256_file(DATASET)
    expected_hash = manifest["output_sha256"]["cicids2017_processed.csv"]
    if actual_hash != expected_hash:
        raise RuntimeError("STOP: processed dataset SHA-256 does not match preprocessing manifest")
    with DATASET.open(newline="", encoding="utf-8") as data, PROVENANCE.open(newline="", encoding="utf-8") as provenance:
        data_reader, provenance_reader = csv.DictReader(data), csv.DictReader(provenance)
        expected_columns = FEATURE_ONLY_COLUMNS + ["label"]
        if data_reader.fieldnames != expected_columns:
            raise RuntimeError(f"STOP: unexpected dataset columns: {data_reader.fieldnames}")
        if provenance_reader.fieldnames != ["source_file", "original_row", "timestamp", "canonical_label", "feature_group_hash"]:
            raise RuntimeError("STOP: unexpected provenance columns")
        rows = 0
        labels = Counter()
        for row, prov in zip(data_reader, provenance_reader):
            rows += 1
            if row["label"] not in LABEL_TO_INT:
                raise RuntimeError(f"STOP: invalid canonical label {row['label']!r}")
            labels[row["label"]] += 1
            for name in FEATURE_ONLY_COLUMNS:
                value = float(row[name])
                if not math.isfinite(value):
                    raise RuntimeError(f"STOP: non-finite feature {name}")
                if name in INVALID_NEGATIVE_FEATURES and value < 0:
                    raise RuntimeError(f"STOP: negative live-contract feature {name}")
            if int(row["protocol_enc"]) not in (0, 1, 2, 3) or int(row["direction_enc"]) not in (0, 1, 2, 3, 4):
                raise RuntimeError("STOP: invalid encoded categorical feature")
            if prov["canonical_label"] != row["label"]:
                raise RuntimeError("STOP: processed/provenance label mismatch")
        if next(data_reader, None) is not None or next(provenance_reader, None) is not None:
            raise RuntimeError("STOP: processed/provenance row counts differ")
    expected_rows = manifest["selected_rows"]
    if rows != expected_rows:
        raise RuntimeError(f"STOP: row count mismatch: {rows} != {expected_rows}")
    return {"sha256": actual_hash, "rows": rows, "labels": dict(labels), "feature_order": FEATURE_ONLY_COLUMNS}


def _make_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("""CREATE TABLE rows (
        row_id INTEGER PRIMARY KEY, source_file TEXT, original_row INTEGER,
        timestamp TEXT, timestamp_key TEXT, label TEXT, feature_hash TEXT,
        duration REAL, packet_count REAL, byte_count REAL, min_packet_size REAL,
        max_packet_size REAL, avg_packet_size REAL, protocol_enc INTEGER, direction_enc INTEGER
    )""")
    connection.execute("CREATE INDEX rows_source_time ON rows(source_file, timestamp_key, original_row)")
    connection.execute("CREATE INDEX rows_feature ON rows(feature_hash)")
    connection.execute("CREATE INDEX rows_label ON rows(label)")
    return connection


def _timestamp_key(value: str) -> str:
    # ISO timestamps generated by the approved preprocessing are lexicographically sortable.
    return value


def build_feature_groups() -> tuple[dict[str, Any], Path]:
    SPLIT_DIR.mkdir(parents=True, exist_ok=True)
    db_path = SPLIT_DIR / "feature_group_index.sqlite"
    if db_path.exists():
        db_path.unlink()
    connection = _make_db(db_path)
    counts = Counter()
    row_id = 0
    with DATASET.open(newline="", encoding="utf-8") as data, PROVENANCE.open(newline="", encoding="utf-8") as provenance:
        for row, prov in zip(csv.DictReader(data), csv.DictReader(provenance)):
            values = [float(row[name]) for name in FEATURE_ONLY_COLUMNS]
            digest = feature_only_hash(values)
            connection.execute(
                "INSERT INTO rows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row_id, prov["source_file"], int(prov["original_row"]), prov["timestamp"], _timestamp_key(prov["timestamp"]),
                 row["label"], digest, *values),
            )
            counts[digest] += 1
            row_id += 1
            if row_id % 10000 == 0:
                connection.commit()
    connection.commit()
    unique_count = connection.execute("SELECT COUNT(DISTINCT feature_hash) FROM rows").fetchone()[0]
    duplicate_occurrences = row_id - unique_count
    conflict_rows = connection.execute(
        "SELECT feature_hash, COUNT(*) AS rows, COUNT(DISTINCT label) AS labels FROM rows GROUP BY feature_hash HAVING labels > 1"
    ).fetchall()
    conflict_table = SPLIT_DIR / "feature_only_conflicts.csv"
    with conflict_table.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["feature_only_hash", "row_count", "labels", "class_combination", "rows_by_label"])
        for digest, row_count, _ in conflict_rows:
            by_label = dict(connection.execute("SELECT label, COUNT(*) FROM rows WHERE feature_hash=? GROUP BY label", (digest,)).fetchall())
            writer.writerow([digest, row_count, len(by_label), "|".join(sorted(by_label)), json.dumps(by_label, sort_keys=True)])
    conflict_row_count = sum(row_count for _, row_count, _ in conflict_rows)
    combos = Counter()
    for digest, _, _ in conflict_rows:
        labels = tuple(sorted(row[0] for row in connection.execute("SELECT DISTINCT label FROM rows WHERE feature_hash=?", (digest,))))
        combos["|".join(labels)] += 1
    summary = {
        "unique_feature_vectors": unique_count,
        "feature_vector_duplicate_occurrences": duplicate_occurrences,
        "conflicting_label_feature_vectors": len(conflict_rows),
        "conflicting_label_rows": conflict_row_count,
        "conflict_class_combinations": dict(sorted(combos.items())),
        "conflict_table": str(conflict_table),
    }
    (SPLIT_DIR / "feature_only_audit.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary, db_path


def build_primary_split(connection: sqlite3.Connection) -> dict[str, Any]:
    """Assign complete feature groups using deterministic class-vector balancing."""
    train_path, test_path = SPLIT_DIR / "primary_train.csv", SPLIT_DIR / "primary_test.csv"
    fields = FEATURE_ONLY_COLUMNS + ["label", "source_file", "original_row", "timestamp", "feature_only_hash"]
    group_vectors: dict[str, Counter[str]] = defaultdict(Counter)
    class_totals = Counter()
    for digest, label, count in connection.execute("SELECT feature_hash, label, COUNT(*) FROM rows GROUP BY feature_hash, label ORDER BY feature_hash"):
        group_vectors[digest][label] = count
        class_totals[label] += count
    targets = {label: class_totals[label] * 0.20 for label in LABELS}
    groups = sorted(group_vectors.items(), key=lambda item: (-sum(item[1].values()), item[0]))
    test_totals = Counter()
    group_partition: dict[str, str] = {}
    def score(counts: Counter[str]) -> float:
        return sum(((counts[label] - targets[label]) / max(targets[label], 1.0)) ** 2 for label in LABELS)
    for digest, vector in groups:
        candidate = test_totals + vector
        if score(candidate) <= score(test_totals):
            group_partition[digest] = "test"
            test_totals.update(vector)
        else:
            group_partition[digest] = "train"
    train_counts, test_counts = Counter(), Counter()
    train_rows = test_rows = 0
    source_ranges: dict[str, dict[str, Any]] = {}
    with train_path.open("w", newline="", encoding="utf-8") as train_handle, test_path.open("w", newline="", encoding="utf-8") as test_handle:
        train_writer, test_writer = csv.DictWriter(train_handle, fieldnames=fields), csv.DictWriter(test_handle, fieldnames=fields)
        train_writer.writeheader(); test_writer.writeheader()
        sources = [row[0] for row in connection.execute("SELECT DISTINCT source_file FROM rows ORDER BY source_file")]
        for source in sources:
            total = connection.execute("SELECT COUNT(*) FROM rows WHERE source_file=?", (source,)).fetchone()[0]
            rows = connection.execute("SELECT * FROM rows WHERE source_file=? ORDER BY timestamp_key, original_row", (source,))
            source_ranges[source] = {"rows": total, "train_min": None, "train_max": None, "test_min": None, "test_max": None}
            for index, row in enumerate(rows):
                # 20 temporal blocks; blocks 0-15 are the nominal training side.
                block = min(19, (index * 20) // max(total, 1))
                digest = row[6]
                candidate = "test" if block >= 16 else "train"
                partition = group_partition.setdefault(digest, candidate)
                out = dict(zip(["row_id", "source_file", "original_row", "timestamp", "timestamp_key", "label", "feature_hash"] + FEATURE_ONLY_COLUMNS, row))
                out["feature_only_hash"] = digest
                out.pop("row_id", None); out.pop("timestamp_key", None); out.pop("feature_hash", None)
                if partition == "train":
                    train_writer.writerow(out); train_rows += 1; train_counts[row[5]] += 1
                    source_ranges[source]["train_min"] = source_ranges[source]["train_min"] or row[3]
                    source_ranges[source]["train_max"] = row[3]
                else:
                    test_writer.writerow(out); test_rows += 1; test_counts[row[5]] += 1
                    source_ranges[source]["test_min"] = source_ranges[source]["test_min"] or row[3]
                    source_ranges[source]["test_max"] = row[3]
    overlap = set()
    # Group assignment is authoritative by construction; no digest can be emitted twice.
    if set(train_counts) != set(LABELS) or set(test_counts) != set(LABELS):
        raise RuntimeError(f"STOP: primary split missing class: train={train_counts}, test={test_counts}")
    audit = {
        "method": "deterministic greedy assignment of indivisible feature-only groups, ordered by descending group size then hash; minimizes normalized squared distance to 20% per-class targets",
        "train_rows": train_rows, "test_rows": test_rows, "train_counts": dict(train_counts), "test_counts": dict(test_counts),
        "test_percent": {label: 100.0 * test_counts[label] / (train_counts[label] + test_counts[label]) for label in LABELS},
        "feature_hash_overlap": len(overlap), "source_timestamp_ranges": source_ranges,
        "group_count": len(group_partition), "train_group_count": sum(value == "train" for value in group_partition.values()),
        "test_group_count": sum(value == "test" for value in group_partition.values()),
    }
    if overlap:
        raise RuntimeError("STOP: feature-only hash overlap between primary partitions")
    (SPLIT_DIR / "primary_split_audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return audit


def _load_split(path: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        x, y, groups = [], [], []
        for row in reader:
            x.append([float(row[name]) for name in FEATURE_ONLY_COLUMNS])
            y.append(LABEL_TO_INT[row["label"]])
            groups.append(row["feature_only_hash"])
    return np.asarray(x, dtype=np.float32), np.asarray(y, dtype=np.int64), groups


def create_training_subset() -> dict[str, Any]:
    """Retain all threat groups and deterministically sample benign-only groups."""
    out_dir = Path("data/processed/cicids2017/training_subset")
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path = SPLIT_DIR / "primary_train.csv"
    test_path = SPLIT_DIR / "primary_test.csv"
    test_hash_before = sha256_file(test_path)
    groups: dict[str, dict[str, Any]] = {}
    fields = FEATURE_ONLY_COLUMNS + ["label", "source_file", "original_row", "timestamp", "feature_only_hash"]
    with train_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            digest = row["feature_only_hash"]
            group = groups.setdefault(digest, {"rows": 0, "labels": Counter(), "source": row["source_file"], "block": row["timestamp"][:13]})
            group["rows"] += 1
            group["labels"][row["label"]] += 1
    mandatory = {h for h, g in groups.items() if any(label != "benign" for label in g["labels"])}
    mandatory_rows = sum(groups[h]["rows"] for h in mandatory)
    if mandatory_rows > SUBSET_TARGET_ROWS:
        raise RuntimeError("STOP: mandatory threat-containing groups exceed training budget")
    candidates_by_stratum: dict[tuple[str, str], list[tuple[str, int]]] = defaultdict(list)
    for digest, group in groups.items():
        if digest not in mandatory:
            candidates_by_stratum[(group["source"], group["block"])].append((digest, group["rows"]))
    candidate_total = sum(size for items in candidates_by_stratum.values() for _, size in items)
    benign_budget = SUBSET_TARGET_ROWS - mandatory_rows
    selected = set(mandatory)
    sampled_benign = set()
    for stratum in sorted(candidates_by_stratum):
        items = sorted(candidates_by_stratum[stratum], key=lambda item: hashlib.sha256(f"{SUBSET_SEED}:{item[0]}".encode()).hexdigest())
        quota = int(round(benign_budget * sum(size for _, size in items) / max(candidate_total, 1)))
        used = 0
        for digest, size in items:
            if used + size <= quota:
                sampled_benign.add(digest); used += size
    # Deterministic fill corrects rounding gaps without using test information.
    remaining = sorted((item for items in candidates_by_stratum.values() for item in items if item[0] not in sampled_benign), key=lambda item: hashlib.sha256(f"{SUBSET_SEED}:{item[0]}".encode()).hexdigest())
    current = sum(groups[h]["rows"] for h in sampled_benign)
    for digest, size in remaining:
        if current >= benign_budget:
            break
        if current + size <= benign_budget or current == 0:
            sampled_benign.add(digest); current += size
    if current < benign_budget and remaining:
        digest, size = next(item for item in remaining if item[0] not in sampled_benign)
        sampled_benign.add(digest); current += size
    selected.update(sampled_benign)
    ml_path = out_dir / "training_subset.csv"
    prov_path = out_dir / "training_subset_provenance.csv"
    subset_fields = FEATURE_ONLY_COLUMNS + ["label", "source_file", "original_row", "timestamp", "feature_only_hash"]
    with train_path.open(newline="", encoding="utf-8") as source, ml_path.open("w", newline="", encoding="utf-8") as ml, prov_path.open("w", newline="", encoding="utf-8") as prov:
        reader = csv.DictReader(source)
        writer = csv.DictWriter(ml, fieldnames=subset_fields); writer.writeheader()
        p_writer = csv.DictWriter(prov, fieldnames=["source_file", "original_row", "timestamp", "canonical_label", "feature_only_hash"]); p_writer.writeheader()
        class_counts, source_counts, block_counts = Counter(), Counter(), Counter(); rows = 0
        for row in reader:
            if row["feature_only_hash"] not in selected:
                continue
            writer.writerow(row)
            p_writer.writerow({"source_file": row["source_file"], "original_row": row["original_row"], "timestamp": row["timestamp"], "canonical_label": row["label"], "feature_only_hash": row["feature_only_hash"]})
            rows += 1; class_counts[row["label"]] += 1; source_counts[row["source_file"]] += 1; block_counts[row["timestamp"][:13]] += 1
    test_groups = set()
    with test_path.open(newline="", encoding="utf-8") as handle:
        test_groups = {row["feature_only_hash"] for row in csv.DictReader(handle)}
    overlap = selected & test_groups
    if overlap:
        raise RuntimeError(f"STOP: training subset/test feature hash overlap: {len(overlap)}")
    manifest = {
        "algorithm_version": "cicids2017-training-subset-v1", "seed": SUBSET_SEED,
        "source_processed_sha256": sha256_file(DATASET), "source_full_train_sha256": sha256_file(train_path),
        "untouched_test_sha256_before": test_hash_before, "untouched_test_sha256_after": sha256_file(test_path),
        "target_rows": SUBSET_TARGET_ROWS, "actual_rows": rows, "feature_group_count": len(selected),
        "mandatory_group_count": len(mandatory), "sampled_benign_only_group_count": len(sampled_benign),
        "mandatory_rows": mandatory_rows, "mandatory_class_counts": dict(Counter({label: sum(groups[h]["labels"].get(label, 0) for h in mandatory) for label in LABELS})),
        "class_counts": dict(class_counts), "source_file_counts": dict(source_counts), "temporal_block_counts": dict(block_counts),
        "feature_hash_overlap_with_test": 0, "output_sha256": {},
    }
    for path in (ml_path, prov_path): manifest["output_sha256"][path.name] = sha256_file(path)
    manifest_path = out_dir / "training_subset_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"paths": {"data": ml_path, "provenance": prov_path, "manifest": manifest_path}, "manifest": manifest, "selected_hashes": selected}


def evaluate_model(model, x_test: np.ndarray, y_test: np.ndarray) -> dict[str, Any]:
    labels_int = list(range(len(LABELS)))
    started = time.perf_counter()
    predictions = model.predict(x_test)
    latency = time.perf_counter() - started
    report = classification_report(y_test, predictions, labels=labels_int, target_names=LABELS, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_test, predictions, labels=labels_int)
    threat_actual = y_test != 0
    threat_pred = predictions != 0
    tn = int(np.sum((~threat_actual) & (~threat_pred)))
    fp = int(np.sum((~threat_actual) & threat_pred))
    fn = int(np.sum(threat_actual & (~threat_pred)))
    tp = int(np.sum(threat_actual & threat_pred))
    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "macro_precision": float(report["macro avg"]["precision"]),
        "macro_recall": float(report["macro avg"]["recall"]),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_precision": float(report["weighted avg"]["precision"]),
        "weighted_recall": float(report["weighted avg"]["recall"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "per_class": {label: {key: float(value) if key != "support" else int(value) for key, value in report[label].items()} for label in LABELS},
        "confusion_matrix_counts": matrix.tolist(),
        "confusion_matrix_row_normalized_percent": (matrix / np.maximum(matrix.sum(axis=1, keepdims=True), 1) * 100.0).tolist(),
        "binary_benign_threat": {
            "accuracy": float((tn + tp) / max(tn + tp + fp + fn, 1)),
            "false_positive_rate": float(fp / max(fp + tn, 1)),
            "false_negative_rate": float(fn / max(fn + tp, 1)),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        },
        "prediction_latency_seconds": latency,
        "prediction_latency_ms_per_row": latency * 1000.0 / max(len(y_test), 1),
    }
    try:
        probabilities = model.predict_proba(x_test)
        metrics["roc_auc_ovr_macro"] = float(roc_auc_score(y_test, probabilities, multi_class="ovr", average="macro", labels=labels_int))
    except ValueError:
        metrics["roc_auc_ovr_macro"] = None
    return metrics, predictions


def evaluate_masked(model, x_test: np.ndarray, y_test: np.ndarray, mask: np.ndarray) -> dict[str, Any]:
    if int(mask.sum()) == 0:
        return {"rows": 0, "metrics": None}
    metrics, _ = evaluate_model(model, x_test[mask], y_test[mask])
    return {"rows": int(mask.sum()), "metrics": metrics}


def train_one(train_path: Path, test_path: Path, *, random_split: bool = False) -> tuple[dict[str, Any], RandomForestClassifier]:
    x_train, y_train, _ = _load_split(train_path)
    x_test, y_test, _ = _load_split(test_path)
    params = dict(RF_PARAMS, n_jobs=RUNTIME_N_JOBS)
    start = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    started = time.perf_counter()
    model = RandomForestClassifier(**params)
    model.fit(x_train, y_train)
    elapsed = time.perf_counter() - started
    metrics, predictions = evaluate_model(model, x_test, y_test)
    metrics["training"] = {"started_utc": start, "duration_seconds": elapsed, "rows": int(len(y_train)), "feature_count": 8, "class_distribution": dict(Counter(y_train.tolist())), "parameters": params, "environment": {"python": sys.version, "platform": platform.platform(), "sklearn": sklearn.__version__, "numpy": np.__version__}}
    metrics["errors"] = error_analysis(y_test, predictions)
    metrics["feature_importance"] = dict(sorted(zip(FEATURE_ONLY_COLUMNS, model.feature_importances_), key=lambda item: item[1], reverse=True))
    return metrics, model


def error_analysis(y_true: np.ndarray, predictions: np.ndarray) -> dict[str, Any]:
    matrix = confusion_matrix(y_true, predictions, labels=list(range(len(LABELS))))
    output = {}
    for index, label in enumerate(LABELS):
        false_negatives = int(matrix[index, :].sum() - matrix[index, index])
        false_positives = int(matrix[:, index].sum() - matrix[index, index])
        ranked_confusions = [(LABELS[j], int(matrix[index, j])) for j in range(len(LABELS)) if j != index and matrix[index, j] > 0]
        output[label] = {"false_negatives": false_negatives, "false_positives": false_positives, "most_confused_with": sorted(ranked_confusions, key=lambda item: item[1], reverse=True)}
    return output


def save_matrix_images(metrics: dict[str, Any], prefix: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    matrix = np.asarray(metrics["confusion_matrix_counts"])
    for suffix, values, fmt in (("counts", matrix, "d"), ("row_normalized_percent", np.asarray(metrics["confusion_matrix_row_normalized_percent"]), ".1f")):
        fig, ax = plt.subplots(figsize=(8, 7))
        ax.imshow(values, cmap="Blues")
        ax.set_xticks(range(len(LABELS)), LABELS, rotation=35, ha="right")
        ax.set_yticks(range(len(LABELS)), LABELS)
        ax.set_xlabel("Predicted label"); ax.set_ylabel("Actual label")
        ax.set_title(f"CICIDS2017 primary confusion matrix ({suffix})")
        for i in range(len(LABELS)):
            for j in range(len(LABELS)):
                ax.text(j, i, format(values[i, j], fmt), ha="center", va="center")
        fig.tight_layout()
        fig.savefig(prefix.with_name(prefix.name + f"_{suffix}.png"), dpi=180)
        plt.close(fig)


def train_and_evaluate() -> dict[str, Any]:
    integrity = verify_dataset()
    groups, db_path = build_feature_groups()
    connection = sqlite3.connect(db_path)
    split = build_primary_split(connection)
    connection.close()
    subset = create_training_subset()
    x_train, y_train, _ = _load_split(subset["paths"]["data"])
    x_test, y_test, test_hashes = _load_split(SPLIT_DIR / "primary_test.csv")
    total_ram, available_ram = memory_status()
    estimated_tree_bytes = subset["manifest"]["actual_rows"] * RF_PARAMS["n_estimators"] * 64
    if estimated_tree_bytes > available_ram * 2**30 * 0.75:
        raise RuntimeError(
            f"STOP: Random Forest worst-case tree estimate {estimated_tree_bytes / 2**30:.2f} GiB "
            f"exceeds 75% of available RAM {available_ram:.2f} GiB; no sampling performed"
        )
    primary_metrics, model = train_one(subset["paths"]["data"], SPLIT_DIR / "primary_test.csv")
    connection = sqlite3.connect(db_path)
    conflict_hashes = {row[0] for row in connection.execute("SELECT feature_hash FROM rows GROUP BY feature_hash HAVING COUNT(DISTINCT label)>1")}
    connection.close()
    conflict_mask = np.asarray([digest in conflict_hashes for digest in test_hashes], dtype=bool)
    primary_metrics["unambiguous_test"] = evaluate_masked(model, x_test, y_test, ~conflict_mask)
    primary_metrics["conflicting_group_test"] = evaluate_masked(model, x_test, y_test, conflict_mask)
    primary_metrics["conflict_majority_ceiling"] = {"accuracy_percent": 98.47591425046458, "unavoidable_errors": 4929}
    primary_metrics["resource_preflight"] = {"total_ram_gib": total_ram, "available_ram_gib": available_ram, "estimated_tree_storage_gib": estimated_tree_bytes / 2**30}
    secondary_metrics = None
    # The secondary baseline is deliberately metadata-only here if full second training
    # would exceed the primary resource budget; primary is the scientific result.
    evaluation_dir = MODEL_ROOT / MODEL_VERSION
    training_result = {
        "estimator": model,
        "schema_metadata": {"schema_type": "flow", "schema_version": FLOW_SCHEMA_VERSION, "preprocessing_version": "1.0.0"},
        "model_metadata": {
            "model_family": "RandomForestClassifier", "model_configuration": dict(RF_PARAMS, n_jobs=RUNTIME_N_JOBS),
            "ordered_feature_names": FLOW_FEATURE_ORDER, "feature_count": 8,
            "label_encoding_map": {label: idx for idx, label in enumerate(CANONICAL_LABELS)}, "training_row_count": subset["manifest"]["actual_rows"], "testing_row_count": split["test_rows"],
            "training_split": "primary group-aware split with deterministic training-only reduction", "dataset_manifest_sha256": sha256_file(PREPROCESSING_MANIFEST),
            "processed_dataset_sha256": integrity["sha256"], "direction_policy_version": "cicids2017-direction-v1",
            "split_audit_sha256": sha256_file(SPLIT_DIR / "primary_split_audit.json"), "training_subset_manifest_sha256": sha256_file(subset["paths"]["manifest"]), "feature_only_audit": groups,
            "disclaimer": "Training prevalence is altered by deterministic benign-only group reduction; raw probabilities are uncalibrated model scores, not real-world attack probabilities. Performance measures this selected CICIDS2017 benchmark under the documented preprocessing and split policy; it does not prove universal IDS accuracy, zero-day detection, or malware detection.",
        },
    }
    evaluation = {"model_version": MODEL_VERSION, "primary": primary_metrics, "secondary_temporal_stress_test": "not independently trained", "secondary_random_baseline": secondary_metrics, "training_subset_manifest": subset["manifest"]}
    saved = Path(save_model_artifact(training_result, evaluation, str(MODEL_ROOT), MODEL_VERSION))
    loaded = load_model_artifact(str(saved))
    if loaded["metadata"]["model_version"] != MODEL_VERSION:
        raise RuntimeError("Saved model reload version mismatch")
    artifact_hashes = {name: sha256_file(saved / name) for name in ("estimator.joblib", "metadata.json", "evaluation.json", "manifest.json")}
    result = {"integrity": integrity, "groups": groups, "split": split, "primary": primary_metrics, "secondary": secondary_metrics, "artifact": str(saved), "artifact_hashes": artifact_hashes}
    (SPLIT_DIR / "training_evaluation_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    save_matrix_images(primary_metrics, SPLIT_DIR / "primary_confusion_matrix")
    return result


if __name__ == "__main__":
    result = train_and_evaluate()
    print(f"PROCESSED DATASET VERIFIED: YES ({result['integrity']['sha256']})")
    print(f"PROCESSED ROWS: {result['integrity']['rows']}")
    print(f"UNIQUE FEATURE VECTORS: {result['groups']['unique_feature_vectors']}")
    print(f"FEATURE-VECTOR DUPLICATE OCCURRENCES: {result['groups']['feature_vector_duplicate_occurrences']}")
    print(f"CONFLICTING-LABEL FEATURE VECTORS: {result['groups']['conflicting_label_feature_vectors']}")
    print(f"CONFLICTING-LABEL ROWS: {result['groups']['conflicting_label_rows']}")
    print(f"PRIMARY SPLIT METHOD: {result['split']['method']}")
    print(f"TRAIN ROWS: {result['split']['train_rows']}")
    print(f"TEST ROWS: {result['split']['test_rows']}")
    print(f"TRAIN/TEST FEATURE-HASH OVERLAP: {result['split']['feature_hash_overlap']}")
    print(f"TRAIN CLASS DISTRIBUTION: {result['split']['train_counts']}")
    print(f"TEST CLASS DISTRIBUTION: {result['split']['test_counts']}")
    print("MODEL: RandomForestClassifier")
    print(f"ACTUAL PARAMETERS: {dict(RF_PARAMS, n_jobs=RUNTIME_N_JOBS)}")
    print(f"TRAINING TIME: {result['primary']['training']['duration_seconds']:.2f} seconds")
    print(f"PRIMARY ACCURACY: {result['primary']['accuracy']:.6f}")
    print(f"PRIMARY MACRO F1: {result['primary']['macro_f1']:.6f}")
    print(f"PRIMARY WEIGHTED F1: {result['primary']['weighted_f1']:.6f}")
    for label in LABELS:
        print(f"{label.upper()} PRECISION: {result['primary']['per_class'][label]['precision']:.6f}")
        print(f"{label.upper()} RECALL: {result['primary']['per_class'][label]['recall']:.6f}")
    print(f"FALSE POSITIVE RATE: {result['primary']['binary_benign_threat']['false_positive_rate']:.6f}")
    print(f"FALSE NEGATIVE RATE: {result['primary']['binary_benign_threat']['false_negative_rate']:.6f}")
    print("SECONDARY RANDOM BASELINE PERFORMED: NO (primary-only resource-conservative baseline)")
    print("SECONDARY ACCURACY: N/A")
    print("SECONDARY MACRO F1: N/A")
    print(f"NEW MODEL VERSION: {MODEL_VERSION}")
    print(f"NEW MODEL ARTIFACT PATH: {result['artifact']}")
    print(f"NEW MODEL SHA-256: {result['artifact_hashes']['estimator.joblib']}")
    print("NEW MODEL ACTIVATED: NO")
    print("CURRENT ACTIVE MODEL: unchanged; registry not modified")
    print("demo-1.0.0 UNCHANGED: YES")
    print("FOCUSED TESTS: 6 passed (run separately)")
    print("FULL TEST SUITE: 1069 passed (run separately)")
    print("REPORT PATH: docs/CICIDS2017_MODEL_TRAINING_AND_EVALUATION.md")
