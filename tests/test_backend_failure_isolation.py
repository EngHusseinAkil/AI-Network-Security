import pytest

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.errors.exceptions import ServiceUnavailableError, InternalApiError

class FailingHealthService:
    def get_health_summary(self):
        # The route shouldn't crash if it returns failed, it should map to 503
        return {"overall_status": "failed", "details": "DB down"}

class ExceptionThrowingModelService:
    def get_active_model(self):
        # Simulates a deep unhandled exception inside a service
        raise RuntimeError("Disk corruption!")

class DependencyCorruptingInferenceService:
    def predict_flow(self, flow_features):
        raise InternalApiError("Model artifact missing")

@pytest.fixture
def fail_app():
    deps = DependencyContainer()
    # Stub these missing ones
    from tests.test_backend_integration import (
        FakeVersionService, FakeAIHealthService,
        FakeDeviceQueryService, FakeTrafficQueryService, FakeThreatQueryService,
        FakeModelService, FakeInferenceService, FakeHealthService
    )
    deps.version_service = FakeVersionService()
    deps.health_service = FailingHealthService()
    deps.ai_health_service = FakeAIHealthService()
    deps.model_service = ExceptionThrowingModelService()
    deps.inference_service = DependencyCorruptingInferenceService()
    deps.device_query_service = FakeDeviceQueryService()
    deps.traffic_query_service = FakeTrafficQueryService()
    deps.threat_query_service = FakeThreatQueryService()

    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    app.config['TESTING_RATE_LIMITS'] = False
    return app

@pytest.fixture
def client(fail_app):
    return fail_app.test_client()

def test_health_503_mapping(client):
    """Proves that a 'failed' health summary correctly maps to a 503 while preserving the envelope."""
    res = client.get('/api/v1/health')
    assert res.status_code == 503
    data = res.get_json()
    assert data["success"] is True  # Health endpoints use success envelope even for 503s!
    assert data["data"]["overall_status"] == "failed"

def test_unhandled_service_exception_isolation(client):
    """Proves an unexpected RuntimeError converts to 500 without crashing the app."""
    res = client.get('/api/v1/models/active')
    assert res.status_code == 500
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "INTERNAL_ERROR"
    # Ensure raw exception text does not leak
    assert "Disk corruption" not in str(data)

def test_api_exception_handling(client):
    """Proves ApiError derivatives are mapped cleanly."""
    payload = {
        "duration": 1.0, "packet_count": 10, "byte_count": 1000,
        "min_packet_size": 100, "max_packet_size": 100, "avg_packet_size": 100.0,
        "protocol_enc": 1, "direction_enc": 2
    }
    res = client.post('/api/v1/inference/flow', json=payload)
    assert res.status_code == 500
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "INTERNAL_ERROR"

def test_failure_does_not_poison_other_endpoints(client):
    """Proves that after a failure, other endpoints still work."""
    # This throws 500
    client.get('/api/v1/models/active')

    # This should work fine
    res = client.get('/api/v1/version')
    assert res.status_code == 200
    assert res.get_json()["success"] is True
