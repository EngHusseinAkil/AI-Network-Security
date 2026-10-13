import pytest
from unittest.mock import patch, MagicMock

from backend.services.ai_health_service import AIHealthService
from backend.services.model_service import ModelService
from backend.errors.exceptions import ServiceUnavailableError

@patch('backend.services.ai_health_service.get_ai_status_report')
def test_ai_health_service_success_mapping(mock_get_ai_status_report):
    mock_get_ai_status_report.return_value = {
        "overall_status": "warning",
        "readiness_level": "configuration_ready",
        "total_checks": 1,
        "checks": [{"name": "Check", "status": "warning"}]
    }

    service = AIHealthService()
    summary = service.get_health_summary()

    assert summary["overall_status"] == "warning"
    assert summary["readiness_level"] == "configuration_ready"
    assert summary["total_checks"] == 1
    assert len(summary["checks"]) == 1

@patch('backend.services.ai_health_service.get_ai_status_report')
def test_ai_health_service_unexpected_exception(mock_get_ai_status_report):
    mock_get_ai_status_report.side_effect = RuntimeError("Explosion")

    service = AIHealthService()
    summary = service.get_health_summary()

    assert summary["overall_status"] == "fail"
    assert summary["failed_checks"] == 1

@patch('backend.services.model_service.ModelRegistry')
def test_model_service_get_models_empty(mock_registry_class):
    mock_registry = MagicMock()
    mock_registry.list_models.return_value = {}
    mock_registry.get_active_model_version.return_value = None
    mock_registry_class.return_value = mock_registry

    service = ModelService("dummy/path")
    data = service.get_models()

    assert data["count"] == 0
    assert data["registry_status"] == "configured"
    assert data["models"] == []

@patch('backend.services.model_service.ModelRegistry')
def test_model_service_get_models_missing(mock_registry_class):
    mock_registry_class.side_effect = FileNotFoundError()

    service = ModelService("dummy/path")
    data = service.get_models()

    assert data["count"] == 0
    assert data["registry_status"] == "not_configured"

@patch('backend.services.model_service.ModelRegistry')
def test_model_service_get_active_none(mock_registry_class):
    mock_registry = MagicMock()
    mock_registry.get_active_model_version.return_value = None
    mock_registry_class.return_value = mock_registry

    service = ModelService("dummy/path")
    data = service.get_active_model()

    assert data["active"] is False
    assert data["status"] == "not_configured"

@patch('backend.services.model_service.ModelRegistry')
def test_model_service_get_active_corrupted_manifest(mock_registry_class):
    mock_registry = MagicMock()
    mock_registry.get_active_model_version.return_value = "v1"
    mock_registry.list_models.return_value = {} # missing manifest
    mock_registry_class.return_value = mock_registry

    service = ModelService("dummy/path")

    with pytest.raises(ServiceUnavailableError) as exc:
        service.get_active_model()

    assert "unavailable" in str(exc.value)
