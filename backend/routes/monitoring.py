"""
Monitoring API Routes.

Provides a single read-only status endpoint consumed by the dashboard
polling JavaScript.  No state mutation, no start/stop controls,
no background threads, no authentication requirement.
"""

import logging
from flask import Blueprint, current_app

from backend.responses import build_success_response
from backend.security import rate_limit

logger = logging.getLogger(__name__)

monitoring_bp = Blueprint("monitoring", __name__)


@monitoring_bp.route("/status", methods=["GET"])
@rate_limit("RATE_LIMIT_DEFAULT")
def get_monitoring_status():
    """
    Returns a read-only monitoring-state snapshot.

    HTTP contract
    -------------
    * 200 – normal: disabled, not_configured, idle, stopped, or running states.
    * 503 – critical monitoring subsystem failure (service object not found).

    The response body always uses the standard success envelope even for
    non-200 statuses, consistent with the health endpoint convention.

    No CSRF token is required; this endpoint is intentionally read-only and
    is consumed by the dashboard polling loop (a GET request with no body).

    Privacy
    -------
    Raw IPs, MACs, payloads, registry paths, database URLs, stack traces,
    and credentials are never included in this response.
    """
    deps = current_app.extensions.get("dependencies")
    if deps is None or not hasattr(deps, "monitoring_service"):
        logger.error("MonitoringStateService not found in application dependencies.")
        return build_success_response(
            data={
                "enabled": False,
                "state": "not_configured",
                "state_display": "Not Configured",
                "note": "Monitoring service is not available.",
            },
            status_code=503,
        )

    try:
        status = deps.monitoring_service.get_status()
        capture_service = getattr(deps, "capture_service", None)
        if capture_service is not None:
            from dashboard.capture_service import serialize_capture_status
            status.update(serialize_capture_status(capture_service.status_snapshot()))
        flow_service = getattr(deps, "dashboard_flow_processing_service", None)
        if flow_service is not None:
            status.update(flow_service.status())
        evaluation_service = getattr(deps, "dashboard_live_flow_evaluation_service", None)
        if evaluation_service is not None:
            status.update(evaluation_service.status())
        notification_service = getattr(
            deps, "dashboard_alert_notification_service", None
        )
        if notification_service is not None:
            status.update(notification_service.status())
        defensive_service = getattr(
            deps, "dashboard_defensive_action_service", None
        )
        if defensive_service is not None:
            status.update(defensive_service.status())
    except Exception:
        logger.exception("Unexpected error fetching monitoring status.")
        return build_success_response(
            data={
                "enabled": False,
                "state": "error",
                "state_display": "Error",
                "note": "Monitoring status could not be retrieved.",
            },
            status_code=503,
        )

    logger.debug(
        "Monitoring status requested. state=%s enabled=%s",
        status.get("state"),
        status.get("enabled"),
    )
    return build_success_response(data=status, status_code=200)
