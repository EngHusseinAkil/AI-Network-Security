import os
import json
import pytest
from unittest.mock import Mock, patch

from ai.health import (
    get_ai_status_report,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_FAIL,
    STATUS_NOT_CONFIGURED,
    READINESS_NOT_READY,
    READINESS_CONFIGURATION_READY,
    READINESS_MODEL_READY,
    READINESS_INTEGRATION_READY
)
from ai.inference import InferenceEngine
from network.features import FLOW_FEATURE_ORDER
from utils.exceptions import ValidationError

@pytest.fixture
def empty_registry(tmp_path):
    registry_file = tmp_path / "registry.json"
    registry_file.write_text(json.dumps({"models": {}, "active_version": None}))
    return str(registry_file)

@pytest.fixture
def mock_models_dir(tmp_path):
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    return str(models_dir)

def test_ai_foundation_passes():
    report = get_ai_status_report(registry_path="nonexistent.json", models_dir="nonexistent")
    # First check is foundation
    foundation_check = report["checks"][0]
    assert foundation_check["name"] == "AI Foundation"
    assert foundation_check["status"] == STATUS_PASS

def test_schema_alignment_passes():
    report = get_ai_status_report(registry_path="nonexistent.json", models_dir="nonexistent")
    schema_check = report["checks"][1]
    assert schema_check["name"] == "Schema Alignment"
    assert schema_check["status"] == STATUS_PASS

def test_no_active_model_produces_warning(empty_registry, mock_models_dir):
    report = get_ai_status_report(registry_path=empty_registry, models_dir=mock_models_dir)
    assert report["overall_status"] == STATUS_WARNING
    assert report["readiness_level"] == READINESS_CONFIGURATION_READY
    active_check = next(c for c in report["checks"] if c["name"] == "Active Model Validation")
    assert active_check["status"] == STATUS_NOT_CONFIGURED

def test_missing_registry_fails_safely():
    report = get_ai_status_report(registry_path="/tmp/does_not_exist_registry.json", models_dir="/tmp")
    assert report["overall_status"] == STATUS_WARNING
    assert report["readiness_level"] == READINESS_CONFIGURATION_READY
    reg_check = next(c for c in report["checks"] if c["name"] == "Model Registry")
    assert reg_check["status"] == STATUS_PASS

def test_corrupt_registry_json_fails_safely(tmp_path):
    registry_file = tmp_path / "corrupt.json"
    registry_file.write_text("{invalid json")
    report = get_ai_status_report(registry_path=str(registry_file), models_dir=str(tmp_path))
    assert report["overall_status"] == STATUS_FAIL
    assert report["readiness_level"] == READINESS_NOT_READY
    reg_check = next(c for c in report["checks"] if c["name"] == "Model Registry")
    assert reg_check["status"] == STATUS_FAIL

@patch("ai.health.InferenceEngine")
@patch("ai.health.load_model_artifact")
def test_valid_active_model_produces_integration_ready(mock_load, mock_engine_cls, tmp_path, mock_models_dir):
    registry_file = tmp_path / "registry.json"
    registry_file.write_text(json.dumps({
        "registered_models": {
            "v1.0.0": {
                "model_dir": str(tmp_path / "models" / "v1.0.0")
            }
        },
        "active_model_version": "v1.0.0"
    }))

    # Touch the artifact file
    (tmp_path / "models" / "v1.0.0").mkdir(parents=True, exist_ok=True)

    mock_load.return_value = {"dummy": "artifact"}

    mock_instance = Mock(spec=InferenceEngine)
    mock_instance.get_model_info.return_value = {
        "model_version": "v1.0.0",
        "schema_version": "1.0.0",
        "feature_count": len(FLOW_FEATURE_ORDER)
    }
    mock_instance.validate_runtime_compatibility.return_value = True
    mock_instance.supports_canonical_label.return_value = True
    mock_engine_cls.return_value = mock_instance

    report = get_ai_status_report(registry_path=str(registry_file), models_dir=mock_models_dir)
    assert report["overall_status"] == STATUS_PASS
    assert report["readiness_level"] == READINESS_INTEGRATION_READY

    active_check = next(c for c in report["checks"] if c["name"] == "Active Model Validation")
    assert active_check["status"] == STATUS_PASS

    integration_check = next(c for c in report["checks"] if c["name"] == "Network Flow Integration")
    assert integration_check["status"] == STATUS_PASS

@patch("ai.health.InferenceEngine")
@patch("ai.health.load_model_artifact")
def test_adapter_compatibility_fails_produces_model_ready(mock_load, mock_engine_cls, tmp_path, mock_models_dir):
    registry_file = tmp_path / "registry.json"
    registry_file.write_text(json.dumps({
        "registered_models": {
            "v1.0.0": {
                "model_dir": str(tmp_path / "models" / "v1.0.0")
            }
        },
        "active_model_version": "v1.0.0"
    }))

    (tmp_path / "models" / "v1.0.0").mkdir(parents=True, exist_ok=True)

    mock_load.return_value = {"dummy": "artifact"}

    mock_instance = Mock(spec=InferenceEngine)
    mock_instance.get_model_info.return_value = {
        "model_version": "v1.0.0",
        "schema_version": "1.0.0",
        "feature_count": len(FLOW_FEATURE_ORDER)
    }
    # Simulate a compatibility failure inside FlowInferenceAdapter
    mock_instance.validate_runtime_compatibility.return_value = False
    mock_engine_cls.return_value = mock_instance

    report = get_ai_status_report(registry_path=str(registry_file), models_dir=mock_models_dir)

    assert report["overall_status"] == STATUS_FAIL
    assert report["readiness_level"] == READINESS_NOT_READY

    integration_check = next(c for c in report["checks"] if c["name"] == "Network Flow Integration")
    assert integration_check["status"] == STATUS_FAIL

def test_public_inference_api_works():
    # Verify the InferenceEngine has the new public API
    assert hasattr(InferenceEngine, "supports_canonical_label")
    assert hasattr(InferenceEngine, "validate_runtime_compatibility")

def test_health_report_privacy():
    report = get_ai_status_report(registry_path="nonexistent.json", models_dir="nonexistent")
    report_str = json.dumps(report)

    # Assert raw IPs or MACs aren't accidentally emitted in default health reports
    assert "192.168." not in report_str
    assert "10.0." not in report_str
    assert "00:00:00:" not in report_str
