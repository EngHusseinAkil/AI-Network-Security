"""
AI endpoints for platform readiness and model management.
"""
import logging
from flask import Blueprint, current_app

from backend.responses import build_success_response
from backend.errors.exceptions import ServiceUnavailableError
from backend.security import rate_limit

logger = logging.getLogger(__name__)

ai_bp = Blueprint('ai', __name__)

@ai_bp.route('/health/ai', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_ai_health():
    """Returns the AI subsystem readiness report."""
    deps = current_app.extensions['dependencies']

    health_data = deps.ai_health_service.get_health_summary()

    overall_status = health_data.get("overall_status", "unknown")

    # HTTP status mapping based on deterministic policy
    status_code = 200
    if overall_status == "fail":
        status_code = 503

    logger.info("AI Health endpoint requested. Mapped status: %s, HTTP: %d", overall_status, status_code)

    return build_success_response(data=health_data, status_code=status_code)

@ai_bp.route('/models', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def list_models():
    """Returns a list of all safely registered models."""
    deps = current_app.extensions['dependencies']
    models_data = deps.model_service.get_models()
    return build_success_response(data=models_data, status_code=200)

@ai_bp.route('/models/active', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_active_model():
    """Returns metadata about the active model safely."""
    deps = current_app.extensions['dependencies']
    active_data = deps.model_service.get_active_model()
    return build_success_response(data=active_data, status_code=200)
