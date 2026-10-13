import json
from flask import Flask, Blueprint, g
from backend.responses import build_success_response, build_error_response
from backend.app_factory import create_app

def test_build_success_response():
    app = Flask(__name__)
    with app.test_request_context():
        g.request_id = "test-req-123"
        response = build_success_response(data={"foo": "bar"}, metadata={"version": "1.0"})
        assert response.status_code == 200

        data = response.get_json()
        assert data["success"] is True
        assert data["data"]["foo"] == "bar"
        assert data["metadata"]["version"] == "1.0"
        assert data["request_id"] == "test-req-123"

def test_build_success_response_empty():
    app = Flask(__name__)
    with app.test_request_context():
        response = build_success_response(status_code=201)
        assert response.status_code == 201

        data = response.get_json()
        assert data["success"] is True
        assert data["data"] == {}
        assert "metadata" not in data

def test_build_error_response():
    app = Flask(__name__)
    with app.test_request_context():
        g.request_id = "test-req-456"
        response = build_error_response(
            code="TEST_ERROR",
            message="A test error occurred.",
            details={"field": "missing"},
            status_code=400
        )
        assert response.status_code == 400

        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "TEST_ERROR"
        assert data["error"]["message"] == "A test error occurred."
        assert data["error"]["details"]["field"] == "missing"
        assert data["request_id"] == "test-req-456"
