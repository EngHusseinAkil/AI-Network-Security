"""
Blueprint definitions.
"""
from flask import Blueprint, jsonify, g

# Minimal internal blueprint to verify registration
internal_bp = Blueprint('internal', __name__)

@internal_bp.route('/_internal/ping', methods=['GET'])
def ping():
    """Temporary route to test blueprint and request ID foundation."""
    return jsonify({
        "success": True,
        "message": "pong",
        "request_id": getattr(g, 'request_id', None)
    })
