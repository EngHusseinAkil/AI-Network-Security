import json
import pytest
from flask import Blueprint, jsonify, request
from werkzeug.exceptions import UnsupportedMediaType

from backend.app_factory import create_app
from backend.security import _rate_limits, rate_limit

@pytest.fixture(autouse=True)
def reset_rate_limits():
    _rate_limits.clear()

@pytest.fixture
def app():
    # We use a custom blueprint to test decorators explicitly without mocking full dependencies
    app = create_app()
    app.config['TESTING'] = True
    app.config['TESTING_RATE_LIMITS'] = True # enable rate limits even in TESTING mode
    app.config['MAX_CONTENT_LENGTH'] = 1024 # 1KB for test
    app.config['CORS_ALLOWED_ORIGINS'] = ['https://trusted.com']

    test_bp = Blueprint('test_security', __name__)

    @test_bp.route('/api/test_json', methods=['POST'])
    def test_json():
        # Force reading to trigger MAX_CONTENT_LENGTH
        data = request.get_json()
        return jsonify({"success": True})

    @test_bp.route('/api/test_rl', methods=['GET'])
    @rate_limit('RATE_LIMIT_DEFAULT')
    def test_rl():
        return jsonify({"success": True})

    app.register_blueprint(test_bp)

    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_secure_headers_present(client):
    res = client.get('/api/v1/health')
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    assert res.headers.get('X-Frame-Options') == 'DENY'
    assert res.headers.get('Referrer-Policy') == 'no-referrer'
    assert res.headers.get('Cache-Control') == 'no-store, max-age=0'
    assert 'default-src' in res.headers.get('Content-Security-Policy', '')
    assert 'geolocation=()' in res.headers.get('Permissions-Policy', '')

def test_json_content_policy_accepts_valid(client):
    res = client.post(
        '/api/test_json',
        data=json.dumps({"test": "data"}),
        content_type='application/json'
    )
    assert res.status_code == 200

def test_json_content_policy_rejects_invalid(client):
    res = client.post(
        '/api/test_json',
        data="test=data",
        content_type='application/x-www-form-urlencoded'
    )
    # The error handler intercepts UnsupportedMediaType and returns standard Api error envelope
    assert res.status_code == 415
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"

def test_payload_too_large(client):
    large_payload = "A" * 2048 # 2KB, exceeds 1KB limit
    res = client.post(
        '/api/test_json',
        data=json.dumps({"data": large_payload}),
        content_type='application/json'
    )
    assert res.status_code == 413
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"

def test_cors_preflight_allowed(client):
    res = client.options(
        '/api/v1/health',
        headers={'Origin': 'https://trusted.com'}
    )
    assert res.status_code == 200
    assert res.headers.get('Access-Control-Allow-Origin') == 'https://trusted.com'

def test_cors_preflight_rejected(client):
    res = client.options(
        '/api/v1/health',
        headers={'Origin': 'https://evil.com'}
    )
    assert res.status_code == 403
    assert 'Access-Control-Allow-Origin' not in res.headers

def test_cors_actual_request_allowed(client):
    res = client.get(
        '/api/v1/health',
        headers={'Origin': 'https://trusted.com'}
    )
    assert res.status_code == 200
    assert res.headers.get('Access-Control-Allow-Origin') == 'https://trusted.com'

def test_cors_actual_request_no_header_for_invalid(client):
    res = client.get(
        '/api/v1/health',
        headers={'Origin': 'https://evil.com'}
    )
    assert res.status_code == 200 # Actual request proceeds, but browser blocks without CORS headers
    assert 'Access-Control-Allow-Origin' not in res.headers

def test_rate_limiting(client, app):
    app.config['RATE_LIMIT_DEFAULT'] = 2

    # 1st request
    res = client.get('/api/test_rl')
    assert res.status_code == 200

    # 2nd request
    res = client.get('/api/test_rl')
    assert res.status_code == 200

    # 3rd request - should fail
    res = client.get('/api/test_rl')
    assert res.status_code == 429
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "retry_after" in data["error"]["details"]
