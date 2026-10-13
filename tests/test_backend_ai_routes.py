import pytest

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.errors.exceptions import ServiceUnavailableError

class FakeAIHealthService:
    def __init__(self, status="pass"):
        self.status = status
    def get_health_summary(self):
        return {
            "overall_status": self.status,
            "readiness_level": "ready"
        }

class FakeModelService:
    def __init__(self, raise_error=False):
        self.raise_error = raise_error
    def get_models(self):
        return {"models": [], "count": 0}
    def get_active_model(self):
        if self.raise_error:
            raise ServiceUnavailableError("Corrupted")
        return {"active": False, "model": None}

@pytest.fixture
def app():
    deps = DependencyContainer()
    deps.ai_health_service = FakeAIHealthService("pass")
    deps.model_service = FakeModelService()

    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_ai_health_pass_returns_200(client):
    response = client.get('/api/v1/health/ai')
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["data"]["overall_status"] == "pass"

def test_ai_health_warning_returns_200(app, client):
    app.extensions['dependencies'].ai_health_service = FakeAIHealthService("warning")
    response = client.get('/api/v1/health/ai')
    assert response.status_code == 200
    data = response.get_json()
    assert data["data"]["overall_status"] == "warning"

def test_ai_health_fail_returns_503(app, client):
    app.extensions['dependencies'].ai_health_service = FakeAIHealthService("fail")
    response = client.get('/api/v1/health/ai')
    assert response.status_code == 503
    data = response.get_json()
    assert data["success"] is True  # Wrapped in success envelope safely
    assert data["data"]["overall_status"] == "fail"

def test_list_models_returns_200(client):
    response = client.get('/api/v1/models')
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["data"]["count"] == 0

def test_active_model_returns_200(client):
    response = client.get('/api/v1/models/active')
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["data"]["active"] is False

def test_active_model_corrupt_returns_503(app, client):
    app.extensions['dependencies'].model_service = FakeModelService(raise_error=True)
    response = client.get('/api/v1/models/active')
    assert response.status_code == 503
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "SERVICE_UNAVAILABLE"
