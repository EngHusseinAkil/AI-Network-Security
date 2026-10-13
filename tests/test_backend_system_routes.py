import pytest
from unittest.mock import patch, MagicMock

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from version import get_project_metadata, get_version

class FakeVersionService:
    def get_version_info(self):
        return {
            "project_name": "Fake Project",
            "application_version": "9.9.9",
            "api_version": "v1"
        }

class FakeHealthService:
    def __init__(self, overall_status="success"):
        self.overall_status = overall_status

    def get_health_summary(self):
        return {
            "overall_status": self.overall_status,
            "total_checks": 1,
            "passed_checks": 1 if self.overall_status == "success" else 0,
            "warning_checks": 1 if self.overall_status == "warning" else 0,
            "failed_checks": 1 if self.overall_status == "failed" else 0,
            "checks": [{"name": "Fake Check", "status": self.overall_status, "message": "Fake message"}]
        }

@pytest.fixture
def test_deps():
    deps = DependencyContainer()
    deps.version_service = FakeVersionService()
    deps.health_service = FakeHealthService("success")
    return deps

@pytest.fixture
def app(test_deps):
    app = create_app(dependencies=test_deps)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_version_endpoint(client):
    response = client.get('/api/v1/version')
    assert response.status_code == 200
    data = response.get_json()

    assert data["success"] is True
    assert data["data"]["project_name"] == "Fake Project"
    assert data["data"]["application_version"] == "9.9.9"
    assert data["data"]["api_version"] == "v1"
    assert "request_id" in data
    assert response.headers.get("X-Request-ID") == data["request_id"]

def test_health_endpoint_success(client):
    response = client.get('/api/v1/health')
    assert response.status_code == 200
    data = response.get_json()

    assert data["success"] is True
    assert data["data"]["overall_status"] == "success"
    assert data["data"]["passed_checks"] == 1
    assert "request_id" in data

def test_health_endpoint_warning_returns_200(app):
    # Reconfigure the fake service
    app.extensions['dependencies'].health_service = FakeHealthService("warning")
    client = app.test_client()

    response = client.get('/api/v1/health')
    assert response.status_code == 200
    data = response.get_json()

    assert data["success"] is True
    assert data["data"]["overall_status"] == "warning"

def test_health_endpoint_failed_returns_503(app):
    # Reconfigure the fake service
    app.extensions['dependencies'].health_service = FakeHealthService("failed")
    client = app.test_client()

    response = client.get('/api/v1/health')
    assert response.status_code == 503
    data = response.get_json()

    # Crucially, the requirement states: "Do not place health failures inside the API error envelope"
    # It should still be a success response wrapper, just with a 503 status code.
    assert data["success"] is True
    assert data["data"]["overall_status"] == "failed"

def test_real_health_service_no_side_effects():
    """Verify the real factory doesn't execute health checks on import or creation."""
    # We patch run_health_check to explode if called
    with patch('backend.services.health_service.run_health_check') as mock_run:
        mock_run.side_effect = RuntimeError("Health check should not be called during app creation")

        # This should not raise an error
        app = create_app()
        assert app is not None
        mock_run.assert_not_called()
