import json
from typing import Dict, Any, List
from flask import request

from backend.errors.exceptions import RequestValidationError
from database.models.alert import Alert

def parse_alert_pagination_params(max_page_size: int = 100) -> Dict[str, Any]:
    """
    Parses pagination and alert-specific filters.
    """
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        raise RequestValidationError("Invalid page parameter. Must be an integer.")

    try:
        page_size = int(request.args.get("page_size", 20))
    except ValueError:
        raise RequestValidationError("Invalid page_size parameter. Must be an integer.")

    if page < 1:
        raise RequestValidationError("Page parameter must be >= 1.")

    if page_size < 1:
        raise RequestValidationError("Page size parameter must be >= 1.")

    if page_size > max_page_size:
        raise RequestValidationError(f"Page size parameter must not exceed {max_page_size}.")

    status = request.args.get("status")
    severity = request.args.get("severity")
    alert_type = request.args.get("alert_type")

    # Simple enum validation to reject obvious garbage early
    if status and status not in ("new", "acknowledged", "resolved", "dismissed"):
        raise RequestValidationError(f"Invalid status filter: {status}")

    if severity and severity not in ("info", "low", "medium", "high", "critical"):
        raise RequestValidationError(f"Invalid severity filter: {severity}")

    return {
        "page": page,
        "page_size": page_size,
        "status": status,
        "severity": severity,
        "alert_type": alert_type
    }

def serialize_alert_summary(alert: Alert) -> Dict[str, Any]:
    """
    Serializes an Alert entity for collection responses.
    Does NOT expose internal IDs or deduplication keys.
    """
    return {
        "public_alert_id": alert.public_alert_id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "status": alert.status,
        "title": alert.title,
        "source_category": alert.source_category,
        "predicted_label": alert.predicted_canonical_label,
        "confidence_score": alert.confidence_score,
        "risk_score": alert.risk_score,
        "model_version": alert.model_version,
        "reason_code": alert.reason_code,
        "occurrence_count": alert.occurrence_count,
        "created_at": alert.created_at.isoformat() if alert.created_at else None
    }

def serialize_alert_detail(alert: Alert) -> Dict[str, Any]:
    """
    Serializes an Alert entity for detail responses.
    Includes additional safe fields, but excludes internal ids.
    """
    base = serialize_alert_summary(alert)

    # Try to parse safe_metadata safely
    metadata_obj = {}
    if alert.safe_metadata:
        try:
            if isinstance(alert.safe_metadata, str):
                metadata_obj = json.loads(alert.safe_metadata)
            elif isinstance(alert.safe_metadata, dict):
                metadata_obj = alert.safe_metadata
        except (ValueError, TypeError):
            # Fallback to empty dict if parsing fails to avoid leaking raw exceptions
            pass

    base.update({
        "description": alert.description,
        "schema_version": alert.schema_version,
        "policy_version": alert.policy_version,
        "acknowledged_at": alert.acknowledged_at,
        "resolved_at": alert.resolved_at,
        "dismissed_at": alert.dismissed_at,
        "safe_metadata": metadata_obj,
        "version": alert.version
    })

    return base
