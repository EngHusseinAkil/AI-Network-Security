import pytest
import json

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from tests.test_backend_database_routes import (
    FakeDeviceQueryService,
    FakeTrafficQueryService,
    FakeThreatQueryService
)

class FakeVersionService:
    def get_version_info(self):
        return {"version": "v1.0.0"}

class FakeHealthService:
    def get_health_summary(self):
        return {"overall_status": "ok"}

class FakeAIHealthService:
    def get_health_summary(self):
        return {"overall_status": "ok"}

class FakeModelService:
    def get_models(self):
        return {"models": []}

    def get_active_model(self):
        return {"active": "model_v1"}

class FakeInferenceService:
    def predict_flow(self, flow_features):
        return {"prediction": 1}

    def predict_flows(self, flows):
        return {"predictions": [1]*len(flows)}

@pytest.fixture
def integration_app():
    deps = DependencyContainer()
    deps.version_service = FakeVersionService()
    deps.health_service = FakeHealthService()
    deps.ai_health_service = FakeAIHealthService()
    deps.model_service = FakeModelService()
    deps.inference_service = FakeInferenceService()
    deps.device_query_service = FakeDeviceQueryService()
    deps.traffic_query_service = FakeTrafficQueryService()
    deps.threat_query_service = FakeThreatQueryService()

    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    app.config['TESTING_RATE_LIMITS'] = False
    return app

@pytest.fixture
def client(integration_app):
    return integration_app.test_client()

def verify_success_envelope(response):
    assert response.status_code == 200
    data = response.get_json()
    assert data is not None
    assert data["success"] is True
    assert "data" in data
    assert "request_id" in data
    assert "error" not in data

    # Headers check
    assert response.headers.get("X-Request-ID") == data["request_id"]
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'

def test_integration_version(client):
    res = client.get('/api/v1/version')
    verify_success_envelope(res)

def test_integration_health(client):
    res = client.get('/api/v1/health')
    verify_success_envelope(res)

def test_integration_ai_health(client):
    res = client.get('/api/v1/health/ai')
    verify_success_envelope(res)

def test_integration_models(client):
    res = client.get('/api/v1/models')
    verify_success_envelope(res)

def test_integration_active_model(client):
    res = client.get('/api/v1/models/active')
    verify_success_envelope(res)

def test_integration_inference_flow(client):
    payload = {
        "duration": 1.0,
        "packet_count": 10,
        "byte_count": 1000,
        "min_packet_size": 100,
        "max_packet_size": 100,
        "avg_packet_size": 100.0,
        "protocol_enc": 1,
        "direction_enc": 2
    }
    res = client.post('/api/v1/inference/flow', json=payload)
    verify_success_envelope(res)

def test_integration_inference_flows(client):
    payload = {
        "flows": [{
            "duration": 1.0,
            "packet_count": 10,
            "byte_count": 1000,
            "min_packet_size": 100,
            "max_packet_size": 100,
            "avg_packet_size": 100.0,
            "protocol_enc": 1,
            "direction_enc": 2
        }]
    }
    res = client.post('/api/v1/inference/flows', json=payload)
    verify_success_envelope(res)

def test_integration_devices(client):
    res = client.get('/api/v1/devices')
    verify_success_envelope(res)

def test_integration_traffic(client):
    res = client.get('/api/v1/traffic')
    verify_success_envelope(res)

def test_integration_threats(client):
    res = client.get('/api/v1/threats')
    verify_success_envelope(res)

def test_dependency_isolation():
    app1 = create_app()
    app2 = create_app()

    deps1 = app1.extensions['dependencies']
    deps2 = app2.extensions['dependencies']

    assert deps1 is not deps2
    assert deps1.inference_service is not deps2.inference_service
    assert deps1.device_query_service is not deps2.device_query_service
