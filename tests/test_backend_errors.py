import pytest
import json
from flask import Blueprint, request

from backend.app_factory import create_app
from backend.errors.exceptions import ModelUnavailableError, RequestValidationError
from utils.exceptions import ValidationError

test_bp = Blueprint('test_errors', __name__, url_prefix='/api/v1/test')

@test_bp.route('/model_unavailable', methods=['GET'])
def trigger_model_unavailable():
    raise ModelUnavailableError()

@test_bp.route('/request_validation', methods=['GET'])
def trigger_request_validation():
    raise RequestValidationError("Validation failed.", details={"missing": ["duration"]})

@test_bp.route('/project_validation', methods=['GET'])
def trigger_project_validation():
    raise ValidationError("Project validation failed.")

@test_bp.route('/unexpected', methods=['GET'])
def trigger_unexpected():
    raise RuntimeError("This is a raw python exception with sensitive stack info")

@test_bp.route('/payload', methods=['POST'])
def trigger_payload():
    data = request.get_json()
    return {"data": data}

@pytest.fixture
def app():
    app = create_app()
    app.register_blueprint(test_bp)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_404_not_found(client):
    response = client.get('/api/v1/does_not_exist')
    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "NOT_FOUND"
    assert "request_id" in data

def test_405_method_not_allowed(client):
    response = client.post('/api/v1/test/model_unavailable')
    assert response.status_code == 405
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "METHOD_NOT_ALLOWED"

def test_400_malformed_json(client):
    # Send bad JSON
    response = client.post('/api/v1/test/payload', data="{bad json}", content_type='application/json')
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "BAD_REQUEST"

def test_415_unsupported_media_type(client):
    # Send wrong content type
    response = client.post('/api/v1/test/payload', data="plain text", content_type='text/plain')
    assert response.status_code == 415
    data = response.get_json()
    assert data["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"

def test_413_payload_too_large(client):
    large_payload = {"data": "x" * (3 * 1024 * 1024)} # 3MB
    response = client.post('/api/v1/test/payload', json=large_payload)
    assert response.status_code == 413
    data = response.get_json()
    assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"

def test_api_model_unavailable(client):
    response = client.get('/api/v1/test/model_unavailable')
    assert response.status_code == 503
    data = response.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "MODEL_UNAVAILABLE"
    assert "request_id" in data

def test_api_request_validation(client):
    response = client.get('/api/v1/test/request_validation')
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert data["error"]["details"]["missing"] == ["duration"]

def test_project_validation_error(client):
    response = client.get('/api/v1/test/project_validation')
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"]["code"] == "VALIDATION_ERROR"

def test_unexpected_exception(client):
    response = client.get('/api/v1/test/unexpected')
    assert response.status_code == 500
    data = response.get_json()
    assert data["error"]["code"] == "INTERNAL_ERROR"
    assert data["error"]["message"] == "An unexpected internal error occurred."
    assert "sensitive stack info" not in str(data)

def test_non_api_404_preserves_flask_behavior(client):
    response = client.get('/some_frontend_route')
    assert response.status_code == 404
    # Should not be a JSON response
    assert b"Not Found" in response.data

def test_request_id_consistency(client):
    response1 = client.get('/api/v1/test/model_unavailable')
    id1_body = response1.get_json()["request_id"]
    id1_header = response1.headers.get("X-Request-ID")
    assert id1_body == id1_header
    assert id1_body is not None

    response2 = client.get('/api/v1/test/model_unavailable')
    id2_body = response2.get_json()["request_id"]
    assert id1_body != id2_body
