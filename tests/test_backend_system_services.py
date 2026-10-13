import pytest
from unittest.mock import patch

from backend.services.version_service import VersionService
from backend.services.health_service import HealthService
from version import get_project_metadata

def test_version_service_metadata():
    service = VersionService(api_version="v2")
    data = service.get_version_info()

    assert data["api_version"] == "v2"
    assert data["project_name"] == get_project_metadata()["project_name"]
    assert "build_date" in data
    assert "application_version" in data
    assert "python_version_min" in data
    # Ensure sensitive or excluded fields are not present
    assert "repository_url" not in data

@patch('backend.services.health_service.run_health_check')
def test_health_service_success_mapping(mock_run_health_check):
    mock_run_health_check.return_value = {
        "overall_status": "success",
        "total_checks": 1,
        "passed": 1,
        "warnings": 0,
        "failed": 0,
        "checks": [
            {"name": "Dummy Check", "status": "success", "message": "All good."}
        ]
    }

    service = HealthService()
    summary = service.get_health_summary()

    assert summary["overall_status"] == "success"
    assert summary["total_checks"] == 1
    assert summary["passed_checks"] == 1
    assert summary["failed_checks"] == 0
    assert len(summary["checks"]) == 1
    assert summary["checks"][0]["name"] == "Dummy Check"
    assert summary["checks"][0]["message"] == "All good."

@patch('backend.services.health_service.run_health_check')
def test_health_service_unexpected_exception(mock_run_health_check):
    mock_run_health_check.side_effect = RuntimeError("Internal failure")

    service = HealthService()
    summary = service.get_health_summary()

    # Should safely catch the error and map it to a failed API response
    assert summary["overall_status"] == "failed"
    assert summary["failed_checks"] == 1
    assert summary["checks"][0]["status"] == "failed"
    assert summary["checks"][0]["message"] == "Health check execution failed."
