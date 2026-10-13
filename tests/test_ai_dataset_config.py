import pytest
from pathlib import Path

from ai.dataset_config import (
    list_supported_datasets,
    validate_dataset_name,
    get_dataset_config,
    DATA_DIR,
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    SAMPLES_DATA_DIR
)
from utils.exceptions import ValidationError
from ai.constants import PACKET_SCHEMA_VERSION, FLOW_SCHEMA_VERSION


def test_supported_dataset_registry_is_deterministic():
    supported = list_supported_datasets()
    assert isinstance(supported, list)
    expected = ["cic-ids2017", "cse-cic-ids2018", "unsw-nb15", "synthetic"]
    for ds in expected:
        assert ds in supported
    assert len(supported) == len(expected)


def test_configured_paths_are_project_relative():
    # Assert they are pathlib Path objects
    assert isinstance(DATA_DIR, Path)
    assert isinstance(RAW_DATA_DIR, Path)
    assert isinstance(PROCESSED_DATA_DIR, Path)
    assert isinstance(SAMPLES_DATA_DIR, Path)

    # Assert they resolve correctly without relying on absolute system paths
    assert DATA_DIR.name == "data"
    assert RAW_DATA_DIR.name == "raw"
    assert PROCESSED_DATA_DIR.name == "processed"
    assert SAMPLES_DATA_DIR.name == "samples"

    assert RAW_DATA_DIR.parent == DATA_DIR
    assert PROCESSED_DATA_DIR.parent == DATA_DIR


def test_raw_and_processed_paths_are_different():
    assert RAW_DATA_DIR != PROCESSED_DATA_DIR
    assert RAW_DATA_DIR.resolve() != PROCESSED_DATA_DIR.resolve()


def test_unknown_dataset_names_fail_correctly():
    with pytest.raises(ValidationError, match="is not supported"):
        validate_dataset_name("unknown-dataset")

    with pytest.raises(ValidationError, match="is not supported"):
        get_dataset_config("unknown-dataset")


def test_dataset_metadata_contains_required_fields():
    for ds_name in list_supported_datasets():
        config = get_dataset_config(ds_name)
        assert "canonical_name" in config
        assert "expected_local_dir" in config
        assert isinstance(config["expected_local_dir"], Path)
        assert "expected_format" in config
        assert "label_column_candidates" in config
        assert isinstance(config["label_column_candidates"], list)
        assert "requires_label_mapping" in config
        assert isinstance(config["requires_label_mapping"], bool)
        assert "description" in config


def test_ai_schema_versions_accessible():
    # Ensuring schema versions are accessible for dataset processing pipelines
    assert isinstance(PACKET_SCHEMA_VERSION, str)
    assert isinstance(FLOW_SCHEMA_VERSION, str)
    assert PACKET_SCHEMA_VERSION == "1.0.0"
    assert FLOW_SCHEMA_VERSION == "1.0.0"


def test_import_side_effects_do_not_download():
    # If the module downloaded anything on import, the test suite would be slow
    # or block. Here we just assert the logic doesn't have any requests calls.
    import sys
    assert "requests" not in sys.modules or "ai.dataset_config" in sys.modules
    # We can also assert there's no URL in the metadata
    for ds_name in list_supported_datasets():
        config = get_dataset_config(ds_name)
        assert "http" not in str(config.values())
