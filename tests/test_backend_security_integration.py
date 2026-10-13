import pytest
import json

from backend.app_factory import create_app
from tests.test_backend_integration import (
    FakeVersionService, FakeHealthService, FakeAIHealthService,
    FakeModelService, FakeInferenceService, FakeDeviceQueryService,
    FakeTrafficQueryService, FakeThreatQueryService
)
from backend.dependencies import DependencyContainer
from backend.security import _rate_limits

@pytest.fixture
def secure_app():
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
    app.config['TESTING_RATE_LIMITS'] = True
    app.config['CORS_ALLOWED_ORIGINS'] = ['https://frontend.internal']
    app.config['RATE_LIMIT_INFERENCE_SINGLE'] = 1 # VERY tight limit for testing

    _rate_limits.clear()

    return app

@pytest.fixture
def client(secure_app):
    return secure_app.test_client()

def test_inference_415_before_service_invocation(client):
    # Sends plaintext instead of JSON
    res = client.post('/api/v1/inference/flow', data="hello", content_type='text/plain')
    assert res.status_code == 415
    data = res.get_json()
    assert data["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"

def test_inference_rate_limiting_integration(client):
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

    # First request: Allowed
    res1 = client.post('/api/v1/inference/flow', json=payload)
    assert res1.status_code == 200

    # Second request: Denied (Limit is 1)
    res2 = client.post('/api/v1/inference/flow', json=payload)
    assert res2.status_code == 429
    data = res2.get_json()
    assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # Third request to a DIFFERENT endpoint: Allowed (separate bucket)
    res3 = client.get('/api/v1/health')
    assert res3.status_code == 200

def test_cors_headers_on_api_responses(client):
    res = client.get('/api/v1/health', headers={'Origin': 'https://frontend.internal'})
    assert res.status_code == 200
    assert res.headers.get('Access-Control-Allow-Origin') == 'https://frontend.internal'

    # But invalid origins get nothing
    res2 = client.get('/api/v1/health', headers={'Origin': 'https://attacker.com'})
    assert res2.status_code == 200
    assert 'Access-Control-Allow-Origin' not in res2.headers

def test_secure_headers_on_errors(client):
    # trigger 404
    res = client.get('/api/v1/nonexistent')
    assert res.status_code == 404
    assert res.headers.get('X-Frame-Options') == 'DENY'
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
