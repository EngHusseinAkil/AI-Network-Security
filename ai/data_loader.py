"""
Safe AI Data Loader.

Provides strict, schema-aware loading of CSV datasets without external ML dependencies
like pandas. Enforces privacy rules by rejecting payload-related columns and validates
all numerical data against the authoritative feature schema.
"""

import csv
import math
from pathlib import Path
from typing import Dict, List, Any, Tuple

from ai.schema import (
    validate_flow_feature_dict,
    validate_packet_feature_dict,
    validate_canonical_label,
    get_flow_schema_metadata,
    get_packet_schema_metadata
)
from ai.dataset_config import get_dataset_config
from network.features import FLOW_FEATURE_ORDER, PACKET_FEATURE_ORDER
from utils.exceptions import ValidationError

FORBIDDEN_COLUMNS = {
    "payload",
    "raw_payload",
    "body",
    "http_body",
    "credentials",
    "token",
    "cookie",
    "packet_bytes"
}

def validate_dataset_columns(columns: List[str], schema_type: str = "flow") -> None:
    """
    Validates that CSV columns match the exact feature order, include a label,
    and do not contain any forbidden payload columns.
    """
    if not isinstance(columns, list):
        raise ValidationError("Columns must be a list of strings.")

    # Check for forbidden columns first (privacy/safety)
    for col in columns:
        if col.lower().strip() in FORBIDDEN_COLUMNS:
            # Do NOT include the column name in the exception to avoid leaking
            # sensitive column structures or user-provided tokens if passed dynamically.
            raise ValidationError("CRITICAL PRIVACY VIOLATION: Forbidden payload or sensitive column detected in dataset.")

    # Determine expected features
    if schema_type == "flow":
        expected_features = FLOW_FEATURE_ORDER
    elif schema_type == "packet":
        expected_features = PACKET_FEATURE_ORDER
    else:
        raise ValidationError(f"Unknown schema_type: {schema_type}")

    # Validate label exists (we assume the last column or a column named 'label')
    if "label" not in [c.lower().strip() for c in columns]:
        raise ValidationError("Dataset must include a 'label' column.")

    # Validate exact order of features (ignoring label column for this check)
    feature_cols = [c for c in columns if c.lower().strip() != "label"]
    if feature_cols != expected_features:
        raise ValidationError(
            f"Dataset feature columns do not match the authoritative {schema_type} schema order exactly."
        )


def validate_dataset_rows(rows: List[Dict[str, Any]], schema_type: str = "flow") -> None:
    """
    Validates every row in the dataset against the strict numeric schema.
    Converts valid strings to floats/ints in-place safely.
    """
    for row in rows:
        label = row.pop("label", None)
        if label is None:
            raise ValidationError("Row is missing a label.")

        validate_canonical_label(label.strip().lower())

        # Safely convert to numeric types
        try:
            for k, v in row.items():
                val = float(v)
                # If it's effectively an integer, store as int to match schema expectations
                if val.is_integer():
                    row[k] = int(val)
                else:
                    row[k] = val
        except ValueError:
            raise ValidationError("Dataset contains non-numeric feature values.")

        # Pass through the authoritative dict validator
        if schema_type == "flow":
            validate_flow_feature_dict(row, strict=True)
        elif schema_type == "packet":
            validate_packet_feature_dict(row, strict=True)


def get_dataset_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Returns a lightweight summary of the dataset.
    """
    label_counts: Dict[str, int] = {}
    for row in rows:
        label = row.get("label", "unknown").strip().lower()
        label_counts[label] = label_counts.get(label, 0) + 1

    return {
        "total_rows": len(rows),
        "label_distribution": label_counts
    }


def load_sample_dataset(path: Path, schema_type: str = "flow") -> Dict[str, Any]:
    """
    Safely loads a tiny local sample dataset without pandas.
    Returns the parsed features, labels, and schema metadata.
    """
    if not isinstance(path, Path):
        path = Path(path)

    if not path.exists() or not path.is_file():
        raise ValidationError("Dataset path does not exist.")

    features_list = []
    labels_list = []

    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            raise ValidationError("Dataset is empty.")

        header = [col.strip() for col in header]
        validate_dataset_columns(header, schema_type)

        raw_rows = []
        for row in reader:
            if len(row) != len(header):
                raise ValidationError("Dataset contains rows with inconsistent lengths.")
            raw_rows.append(dict(zip(header, row)))

    # Process and validate the raw rows
    validate_dataset_rows(raw_rows, schema_type)

    # After validation, extract labels and rebuild the feature lists
    # validate_dataset_rows pops the label out of the dict, so raw_rows now contains just features
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for validated_features, raw_row in zip(raw_rows, reader):
            labels_list.append(raw_row["label"].strip().lower())
            features_list.append(validated_features)

    # Prepare return contract
    metadata = get_flow_schema_metadata() if schema_type == "flow" else get_packet_schema_metadata()

    return {
        "features": features_list,
        "labels": labels_list,
        "schema_metadata": metadata,
        "row_count": len(features_list),
        "source_path": str(path.resolve())
    }


def load_registered_dataset_sample(name: str) -> Dict[str, Any]:
    """
    Loads the designated sample dataset for a registered canonical name.
    """
    config = get_dataset_config(name)
    path = config["expected_local_dir"]

    # If this is the synthetic test fixture, point directly to the tiny CSV
    if name == "synthetic":
        path = path.parent / "tiny_flow_sample.csv"

    return load_sample_dataset(path, schema_type="flow")
