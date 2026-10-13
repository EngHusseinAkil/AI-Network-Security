"""
Dataset Configuration and Registry.

Safety Rules:
1. Raw external datasets are immutable inputs.
2. Processed datasets must never overwrite raw files.
3. Large datasets must stay outside Git.
4. Source labels must not be silently replaced. Future adapters must preserve
   source-label traceability.
5. Dataset preprocessing must ultimately produce features compatible with the
   versioned AI schema (PACKET_SCHEMA_VERSION, FLOW_SCHEMA_VERSION).
6. Training and runtime feature contracts must remain aligned.
"""

from pathlib import Path
from typing import Dict, Any, List
from utils.exceptions import ValidationError

# Project Root (Assumes this file is in ai/ and the root is one level up)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Safe relative paths
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLES_DATA_DIR = DATA_DIR / "samples"

# Define dataset configuration metadata
_DATASET_REGISTRY: Dict[str, Dict[str, Any]] = {
    "cic-ids2017": {
        "canonical_name": "cic-ids2017",
        "expected_local_dir": RAW_DATA_DIR / "cic-ids2017",
        "expected_format": "csv",
        "label_column_candidates": ["Label", " Label"],
        "requires_label_mapping": True,
        "description": "CIC-IDS2017 dataset containing benign and common attack flows."
    },
    "cse-cic-ids2018": {
        "canonical_name": "cse-cic-ids2018",
        "expected_local_dir": RAW_DATA_DIR / "cse-cic-ids2018",
        "expected_format": "csv",
        "label_column_candidates": ["Label"],
        "requires_label_mapping": True,
        "description": "CSE-CIC-IDS2018 dataset generated on AWS."
    },
    "unsw-nb15": {
        "canonical_name": "unsw-nb15",
        "expected_local_dir": RAW_DATA_DIR / "unsw-nb15",
        "expected_format": "csv",
        "label_column_candidates": ["attack_cat", "label"],
        "requires_label_mapping": True,
        "description": "UNSW-NB15 dataset with comprehensive modern attack behaviors."
    },
    "synthetic": {
        "canonical_name": "synthetic",
        "expected_local_dir": SAMPLES_DATA_DIR / "synthetic",
        "expected_format": "csv",
        "label_column_candidates": ["label"],
        "requires_label_mapping": False,
        "description": "Tiny safe synthetic/documentation-safe fixtures for tests."
    }
}


def list_supported_datasets() -> List[str]:
    """Returns a list of canonically supported dataset names."""
    return list(_DATASET_REGISTRY.keys())


def validate_dataset_name(name: str) -> None:
    """
    Validates if a dataset name is supported by the registry.
    Raises ValidationError if not supported.
    """
    if not isinstance(name, str) or name not in _DATASET_REGISTRY:
        raise ValidationError(
            f"Dataset '{name}' is not supported. Supported datasets: {list_supported_datasets()}"
        )


def get_dataset_config(name: str) -> Dict[str, Any]:
    """
    Retrieves configuration metadata for a registered dataset.
    Raises ValidationError if the dataset is unknown.
    """
    validate_dataset_name(name)
    # Return a shallow copy to prevent accidental mutation of the registry
    return _DATASET_REGISTRY[name].copy()
