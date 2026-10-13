import pytest
from flask import Blueprint, jsonify

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from tests.test_backend_integration import (
    FakeVersionService, FakeHealthService, FakeAIHealthService,
    FakeModelService, FakeInferenceService, FakeDeviceQueryService,
    FakeTrafficQueryService, FakeThreatQueryService
)

@pytest.fixture
def perfect_app():
    deps = DependencyContainer()
    deps.version_service = FakeVersionService()
    deps.health_service = FakeHealthService()
    deps.ai_health_service = FakeAIHealthService()
    deps.model_service = FakeModelService()
    deps.inference_service = FakeInferenceService()
    deps.device_query_service = FakeDeviceQueryService()
    deps.traffic_query_service = FakeTrafficQueryService()
    deps.threat_query_service = FakeThreatQueryService()
    # It mocks a perfectly initialized app with all deps
    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    app.config['DEBUG'] = False
    app.config['CORS_ALLOWED_ORIGINS'] = ['https://trusted.internal']
    app.config['MAX_CONTENT_LENGTH'] = 1048576
    app.config['RATE_LIMIT_DEFAULT'] = 60
    return app

@pytest.fixture
def perfect_client(perfect_app):
    return perfect_app.test_client()

def test_backend_health_perfect_state(perfect_client):
    res = perfect_client.get('/api/v1/health/backend')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    health = data["data"]
    assert health["overall_status"] == "warning" # Has in-memory limiter warning!
    assert health["readiness_level"] == "integration_ready"
    assert health["failed_checks"] == 0
    assert "request_id" in data
    assert res.headers.get("X-Request-ID") == data["request_id"]

def test_backend_health_critical_failure():
    """Simulates a critical failure (e.g. missing route or bad CORS)."""
    deps = DependencyContainer()
    deps.version_service = FakeVersionService()
    deps.health_service = FakeHealthService()
    deps.ai_health_service = FakeAIHealthService()
    deps.model_service = FakeModelService()
    deps.inference_service = FakeInferenceService()
    # Missing DB queries triggers service missing -> 503
    app = create_app(dependencies=deps)
    app.config['TESTING'] = True

    # Also add wildcard CORS to guarantee critical fail
    app.config['CORS_ALLOWED_ORIGINS'] = ['*']

    client = app.test_client()
    res = client.get('/api/v1/health/backend')

    assert res.status_code == 503
    data = res.get_json()
    assert data["success"] is True # Still uses success envelope!

    health = data["data"]
    assert health["overall_status"] == "failed"
    assert health["readiness_level"] == "not_ready"
    assert health["failed_checks"] > 0

    cors_check = next((c for c in health["checks"] if c["name"] == "CORS Policy"), None)
    assert cors_check["status"] == "fail"

def test_backend_health_duplicate_route():
    """Test prefix validation logic (fails safely if invalid routes exist)."""
    app = create_app()
    app.config['TESTING'] = True

    bad_bp = Blueprint('bad', __name__)
    @bad_bp.route('/api/v2/unexpected', methods=['GET'])
    def unexpected():
        return jsonify({"test": True})

    app.register_blueprint(bad_bp)

    client = app.test_client()
    res = client.get('/api/v1/health/backend')

    # 503 because the API Prefix Consistency check will fail
    assert res.status_code == 503
    health = res.get_json()["data"]

    prefix_check = next((c for c in health["checks"] if c["name"] == "API Prefix Consistency"), None)
    assert prefix_check is not None
    assert prefix_check["status"] == "fail"
    assert "non-v1 API routes" in prefix_check["message"]

def test_backend_health_no_db():
    """Test database missing safely marks as not configured."""
    deps = DependencyContainer()
    deps.version_service = FakeVersionService()
    deps.health_service = FakeHealthService()
    deps.ai_health_service = FakeAIHealthService()
    deps.model_service = FakeModelService()
    deps.inference_service = FakeInferenceService()
    deps.device_query_service = FakeDeviceQueryService()
    deps.traffic_query_service = FakeTrafficQueryService()
    deps.threat_query_service = FakeThreatQueryService()

    # explicitly None
    deps.db_session = None

    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    client = app.test_client()

    res = client.get('/api/v1/health/backend')
    health = res.get_json()["data"]

    db_check = next((c for c in health["checks"] if c["name"] == "Database Factory"), None)
    assert db_check["status"] == "not_configured"
    # overall should be warning, NOT 503
    assert res.status_code == 200
