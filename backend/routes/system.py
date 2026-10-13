"""
System endpoints for platform health and versioning.
"""
import logging
from flask import Blueprint, current_app

from backend.responses import build_success_response
from backend.security import rate_limit

logger = logging.getLogger(__name__)

system_bp = Blueprint('system', __name__)

@system_bp.route('/version', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_version():
    """Returns safe project metadata and API versions."""
    deps = current_app.extensions['dependencies']
    version_data = deps.version_service.get_version_info()
    return build_success_response(data=version_data, status_code=200)

@system_bp.route('/health', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_health():
    """Returns the overall platform health status."""
    deps = current_app.extensions['dependencies']

    # We retrieve the safe API contract from the service layer
    health_data = deps.health_service.get_health_summary()

    status_code = 200
    overall_status = health_data.get("overall_status", "unknown")

    # HTTP status mapping based on policy
    if overall_status == "failed":
        status_code = 503

    logger.info("Health endpoint requested. Mapped status: %s, HTTP: %d", overall_status, status_code)

    # We still use the success envelope even for 503 as per requirement 8:
    # "Do not place health failures inside the API error envelope when the endpoint completed normally."
    return build_success_response(data=health_data, status_code=status_code)

@system_bp.route('/health/backend', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_backend_health():
    """Returns the backend/API specific readiness report."""
    deps = current_app.extensions['dependencies']

    health_data = deps.backend_health_service.get_health_summary()

    status_code = 200
    overall_status = health_data.get("overall_status", "unknown")

    # HTTP status mapping
    if overall_status == "failed":
        status_code = 503

    logger.info("Backend Health endpoint requested. Mapped status: %s, HTTP: %d", overall_status, status_code)

    return build_success_response(data=health_data, status_code=status_code)
