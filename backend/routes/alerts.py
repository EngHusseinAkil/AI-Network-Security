"""
Read-Only API Routes for Alerts.
"""
import logging
from flask import Blueprint, current_app, request

from backend.responses import build_success_response, build_error_response
from backend.schemas.alerts import parse_alert_pagination_params
from backend.errors.exceptions import RequestValidationError
from backend.security import rate_limit

logger = logging.getLogger(__name__)

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def list_alerts():
    """
    List alerts with bounded pagination and safe filtering.
    """
    try:
        params = parse_alert_pagination_params()
    except RequestValidationError as e:
        return build_error_response("VALIDATION_ERROR", str(e), status_code=400)

    deps = current_app.extensions['dependencies']

    filters = {
        'status': params['status'],
        'severity': params['severity'],
        'alert_type': params['alert_type']
    }

    result = deps.alert_persistence_service.get_alerts(
        page=params['page'],
        page_size=params['page_size'],
        filters=filters
    )

    logger.info("Listed alerts page %d with size %d", params['page'], params['page_size'])
    return build_success_response(data=result['alerts'], metadata=result['pagination'])


@alerts_bp.route('/<string:public_alert_id>', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_alert(public_alert_id: str):
    """
    Get alert detail by public identifier.
    """
    deps = current_app.extensions['dependencies']

    result = deps.alert_persistence_service.get_alert(public_alert_id)
    if not result:
        return build_error_response("NOT_FOUND", "Alert not found", status_code=404)

    return build_success_response(data=result)
