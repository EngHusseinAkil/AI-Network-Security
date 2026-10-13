"""
Read-Only Database API Routes.
"""
import logging
from flask import Blueprint, current_app

from backend.responses import build_success_response
from backend.schemas.database import parse_pagination_params
from backend.security import rate_limit

logger = logging.getLogger(__name__)

db_bp = Blueprint('database', __name__)

@db_bp.route('/devices', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def list_devices():
    params = parse_pagination_params()
    deps = current_app.extensions['dependencies']
    result = deps.device_query_service.get_devices(params['page'], params['page_size'])
    logger.info("Listed devices page %d with size %d", params['page'], params['page_size'])
    return build_success_response(data=result)

@db_bp.route('/devices/<int:device_id>', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_device(device_id: int):
    deps = current_app.extensions['dependencies']
    result = deps.device_query_service.get_device(device_id)
    return build_success_response(data=result)

@db_bp.route('/traffic', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def list_traffic():
    params = parse_pagination_params()
    deps = current_app.extensions['dependencies']
    result = deps.traffic_query_service.get_traffic(params['page'], params['page_size'])
    logger.info("Listed traffic records page %d with size %d", params['page'], params['page_size'])
    return build_success_response(data=result)

@db_bp.route('/traffic/<int:record_id>', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_traffic_record(record_id: int):
    deps = current_app.extensions['dependencies']
    result = deps.traffic_query_service.get_traffic_record(record_id)
    return build_success_response(data=result)

@db_bp.route('/threats', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def list_threats():
    params = parse_pagination_params()
    deps = current_app.extensions['dependencies']
    result = deps.threat_query_service.get_threats(params['page'], params['page_size'])
    logger.info("Listed threat logs page %d with size %d", params['page'], params['page_size'])
    return build_success_response(data=result)

@db_bp.route('/threats/<int:threat_id>', methods=['GET'])
@rate_limit('RATE_LIMIT_DEFAULT')
def get_threat(threat_id: int):
    deps = current_app.extensions['dependencies']
    result = deps.threat_query_service.get_threat(threat_id)
    return build_success_response(data=result)
