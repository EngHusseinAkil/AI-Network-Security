"""
Standardized API Response Helpers.
"""
from flask import jsonify, g

def build_success_response(data=None, metadata=None, status_code=200):
    """
    Builds a standardized success JSON response.

    Format:
    {
        "success": true,
        "data": { ... },
        "metadata": { ... },
        "request_id": "req-uuid"
    }
    """
    if data is None:
        data = {}

    response_data = {
        "success": True,
        "data": data
    }

    if metadata is not None:
        response_data["metadata"] = metadata

    if hasattr(g, 'request_id'):
        response_data["request_id"] = g.request_id

    response = jsonify(response_data)
    response.status_code = status_code
    return response

def build_error_response(code: str, message: str, details=None, status_code=500):
    """
    Builds a standardized error JSON response.

    Format:
    {
        "success": false,
        "error": {
            "code": "CODE",
            "message": "User-friendly message",
            "details": { ... }
        },
        "request_id": "req-uuid"
    }
    """
    error_payload = {
        "code": code,
        "message": message
    }

    if details is not None:
        error_payload["details"] = details

    response_data = {
        "success": False,
        "error": error_payload
    }

    if hasattr(g, 'request_id'):
        response_data["request_id"] = g.request_id

    response = jsonify(response_data)
    response.status_code = status_code
    return response
