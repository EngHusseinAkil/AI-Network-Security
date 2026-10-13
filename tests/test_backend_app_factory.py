import pytest
from flask import Flask
from backend.app_factory import create_app

def test_create_app_returns_flask_app():
    """Test that create_app returns a valid Flask instance."""
    app = create_app()
    assert isinstance(app, Flask)

def test_app_multiple_creation():
    """Test that app can be created multiple times safely."""
    app1 = create_app()
    app2 = create_app()
    assert app1 is not app2
    assert app1.config is not app2.config

def test_config_override():
    """Test that configuration overrides work."""
    app = create_app({"CUSTOM_KEY": "CUSTOM_VALUE"})
    assert app.config["CUSTOM_KEY"] == "CUSTOM_VALUE"

def test_testing_flag_is_false_by_default():
    app = create_app()
    assert app.config.get("TESTING") is False
    assert app.config.get("DEBUG") is False

def test_blueprint_registration_and_api_prefix():
    """Test that blueprints are registered with correct prefix."""
    app = create_app()
    client = app.test_client()

    # Internal ping uses prefix /api/v1
    response = client.get('/api/v1/_internal/ping')
    assert response.status_code == 200
    data = response.get_json()
    assert data["message"] == "pong"
    assert "request_id" in data

def test_request_id_generation():
    """Test request IDs are generated as UUIDs."""
    app = create_app()
    client = app.test_client()

    response = client.get('/api/v1/_internal/ping')
    data = response.get_json()
    assert "request_id" in data
    assert data["request_id"] is not None
    assert "-" in data["request_id"]  # simple UUID check

    # Check header
    assert 'X-Request-ID' in response.headers
    assert response.headers['X-Request-ID'] == data["request_id"]

def test_error_handler_404_json():
    """Test safe JSON returns for 404 on API endpoints."""
    app = create_app()
    client = app.test_client()

    response = client.get('/api/v1/does_not_exist')
    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "NOT_FOUND"
    assert "request_id" in data

def test_error_handler_405_json():
    """Test safe JSON returns for 405 on API endpoints."""
    app = create_app()
    client = app.test_client()

    # Send POST to a GET-only internal endpoint
    response = client.post('/api/v1/_internal/ping')
    assert response.status_code == 405
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert "request_id" in data

def test_logger_handlers_not_duplicated():
    """Ensure that repeated app creations don't multiply logger handlers."""
    from utils.logger import get_logger
    base_logger = get_logger("FlaskApp")
    initial_count = len(base_logger.handlers)

    app1 = create_app()
    app2 = create_app()

    # Flask app logger might wrap the handlers, but we want to ensure we aren't adding handlers infinitely
    assert len(app2.logger.handlers) <= initial_count

def test_side_effect_safety():
    """
    Ensure no side-effects (model loading, DB connection, network capture)
    happen simply by creating the app.
    """
    app = create_app()
    deps = app.extensions.get('dependencies')
    assert deps is not None
    assert deps.db_session is None
    assert deps.health_service is not None
    assert deps.version_service is not None
    assert deps.ai_health_service is not None
    assert deps.model_service is not None
    assert deps.inference_service is not None
    assert deps.device_query_service is not None
    assert deps.traffic_query_service is not None
    assert deps.threat_query_service is not None
