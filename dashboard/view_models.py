"""
Dashboard view models.
"""
from version import VERSION as app_version, PROJECT_NAME

def get_base_view_model(page_title: str) -> dict:
    """
    Returns a safe base view model for rendering dashboard templates.
    """
    return {
        "project_name": PROJECT_NAME,
        "page_title": page_title,
        "app_version": app_version,
        "api_version": "v1",
        "dashboard_status": None,
        "active_nav_key": "overview",
        "breadcrumbs": [
            {"name": "Home", "url": "/dashboard/"},
            {"name": page_title, "url": None}
        ],
        "feature_availability": {
            "monitoring": True,
            "api_ready": True
        },
        "nav_items": [
            {"key": "overview",    "name": "Overview",    "url": "/dashboard/",          "enabled": True},
            {"key": "health",      "name": "Health",      "url": "/dashboard/health",    "enabled": True},
            {"key": "models",      "name": "Models",      "url": "/dashboard/models",    "enabled": True},
            {"key": "devices",     "name": "Devices",     "url": "/dashboard/devices",   "enabled": True},
            {"key": "traffic",     "name": "Traffic",     "url": "/dashboard/traffic",   "enabled": True},
            {"key": "threats",     "name": "Threats",     "url": "/dashboard/threats",   "enabled": True},
            {"key": "inference",   "name": "Inference",   "url": "/dashboard/inference", "enabled": True},
            {"key": "monitoring",  "name": "Monitoring",  "url": "/dashboard/monitoring","enabled": True},
            {"key": "alerts",      "name": "Alerts",      "url": "/dashboard/alerts",    "enabled": True},
        ]
    }

def normalize_status(status_str: str) -> str:
    """Normalize service status to safe UI classes."""
    if not status_str:
        return 'unknown'

    s = status_str.lower()

    if s in ['pass', 'success', 'ready', 'model_ready', 'integration_ready', 'transport_ready', 'services_ready', 'configuration_ready']:
        return 'success'
    elif s in ['warning']:
        return 'warning'
    elif s in ['fail', 'failed', 'not_ready']:
        return 'danger'
    elif s in ['not_configured', 'skipped', 'unknown']:
        return 'info'

    return 'unknown'

def summarize_checks(checks: list) -> dict:
    """Summarize checks into counts."""
    counts = {
        'total': len(checks),
        'success': 0,
        'warning': 0,
        'danger': 0,
        'info': 0,
        'unknown': 0
    }

    for check in checks:
        status = normalize_status(check.get('status', 'unknown'))
        check['ui_status'] = status
        counts[status] += 1

    return counts

def build_health_view_model(page_title: str, health_data: dict, subsystem_name: str) -> dict:
    """Build a safe view model for a health detail page."""
    base = get_base_view_model(page_title)

    # Enable health nav
    base["active_nav_key"] = "health"
    for item in base["nav_items"]:
        if item["key"] == "health":
            item["enabled"] = True
            item["url"] = "/dashboard/health"

    # Add breadcrumbs
    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": "Health Overview", "url": "/dashboard/health"},
        {"name": subsystem_name, "url": None}
    ]

    checks = health_data.get('checks', [])
    summary_counts = summarize_checks(checks)
    overall_status = normalize_status(health_data.get('overall_status', 'unknown'))

    base.update({
        "subsystem_name": subsystem_name,
        "overall_status": overall_status,
        "message": health_data.get('message', ''),
        "readiness_level": health_data.get('readiness_level', ''),
        "checks": checks,
        "summary_counts": summary_counts,
        "error_category": health_data.get('error_category')
    })

    return base

def build_health_overview_view_model(system_health: dict, ai_health: dict, backend_health: dict) -> dict:
    """Build view model for the health overview page."""
    base = get_base_view_model("System Health")

    base["active_nav_key"] = "health"
    for item in base["nav_items"]:
        if item["key"] == "health":
            item["enabled"] = True
            item["url"] = "/dashboard/health"

    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": "Health Overview", "url": None}
    ]

    def _extract_summary(data, name):
        status = normalize_status(data.get('overall_status', 'unknown'))
        checks = data.get('checks', [])
        return {
            "name": name,
            "overall_status": status,
            "message": data.get('message', ''),
            "total_checks": len(checks)
        }

    base.update({
        "system_summary": _extract_summary(system_health, "System Core"),
        "ai_summary": _extract_summary(ai_health, "AI Engine"),
        "backend_summary": _extract_summary(backend_health, "Backend APIs"),
    })

    return base

def _enable_nav_key(base: dict, nav_key: str, url: str):
    base["active_nav_key"] = nav_key
    for item in base["nav_items"]:
        if item["key"] == nav_key:
            item["enabled"] = True
            item["url"] = url

def build_model_overview_view_model(model_data: dict) -> dict:
    """Build view model for model overview."""
    base = get_base_view_model("Model Overview")
    _enable_nav_key(base, "models", "/dashboard/models")

    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": "Models", "url": None}
    ]
    base["model_data"] = model_data
    return base

def build_collection_view_model(page_title: str, nav_key: str, data: dict, url_base: str) -> dict:
    """Build view model for paginated collection."""
    base = get_base_view_model(page_title)
    _enable_nav_key(base, nav_key, url_base)

    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": page_title, "url": None}
    ]
    base["data"] = data
    return base

def build_detail_view_model(page_title: str, nav_key: str, data: dict, url_base: str) -> dict:
    """Build view model for detail view."""
    base = get_base_view_model(page_title)
    _enable_nav_key(base, nav_key, url_base)

    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": page_title.split(" ")[0] + "s", "url": url_base}, # Best effort plural
        {"name": page_title, "url": None}
    ]
    base["data"] = data
    return base

def build_inference_view_model(form_data: dict = None, result_data: dict = None, error: str = None) -> dict:
    """Builds the view model for the inference submission page."""
    base = get_base_view_model("Inference")
    base["active_nav_key"] = "inference"

    for item in base["nav_items"]:
        if item["key"] == "inference":
            item["enabled"] = True
            item["url"] = "/dashboard/inference"

    base["form"] = form_data or {}
    base["result"] = result_data
    base["error"] = error
    return base


# ---------------------------------------------------------------------------
# State display helpers (shared with monitoring page)
# ---------------------------------------------------------------------------

# Maps allowlisted MonitoringState tokens -> human-readable display labels.
# Only values in this mapping are safe to use as badge classes.
_MONITORING_STATE_DISPLAY = {
    "disabled":       ("Disabled",        "info"),
    "idle":           ("Idle",             "info"),
    "starting":       ("Starting",         "warning"),
    "running":        ("Running",          "success"),
    "degraded":       ("Degraded",         "warning"),
    "stopped":        ("Stopped",          "info"),
    "error":          ("Error",            "danger"),
    "not_configured": ("Not Configured",   "info"),
    "unknown":        ("Unknown",          "info"),
    "simulation_complete": ("Simulation Complete", "success"),
}


def monitoring_state_display(state: str):
    """
    Return (display_label, badge_class) for *state*.

    Only allowlisted states produce badge classes; everything else maps to
    the 'unknown' fallback so arbitrary strings never reach the template.
    """
    return _MONITORING_STATE_DISPLAY.get(state, ("Unknown", "info"))


def build_monitoring_view_model(status: dict, capture_status: dict = None, interfaces=(),
                                flow_status: dict = None, evaluation_status: dict = None) -> dict:
    """
    Build the view model for the dashboard monitoring page.

    Parameters
    ----------
    status : dict
        The dict returned by MonitoringStateService.get_status().

    The view model adds display-friendly labels and safe badge classes
    derived from an allowlist; raw state tokens from the service are not
    forwarded directly to templates as CSS classes.
    """
    base = get_base_view_model("Monitoring")
    base["active_nav_key"] = "monitoring"
    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": "Monitoring", "url": None},
    ]

    raw_state = status.get("state", "unknown")
    display_label, badge_class = monitoring_state_display(raw_state)

    base["monitoring"] = {
        "enabled":               bool(status.get("enabled", False)),
        "state":                 raw_state,
        "state_display":         display_label,
        "state_badge_class":     badge_class,
        "last_successful_cycle": status.get("last_successful_cycle"),
        "last_error_category":   status.get("last_error_category"),
        "health_summary":        status.get("health_summary", {}),
        "active_model_version":  status.get("active_model_version"),
        # Counters: always integers, never fabricated.
        "processed_flow_count":  int(status.get("processed_flow_count", 0)),
        "prediction_count":      int(status.get("prediction_count", 0)),
        "alert_count":           int(status.get("alert_count", 0)),

        # Simulation specific metrics
        "simulation_cycle_count": int(status.get("simulation_cycle_count", 0)),
        "simulated_flow_count": int(status.get("simulated_flow_count", 0)),
        "successful_simulation_inference_count": int(status.get("successful_simulation_inference_count", 0)),
        "failed_simulation_inference_count": int(status.get("failed_simulation_inference_count", 0)),
        "simulation_recommendation_count": int(status.get("simulation_recommendation_count", 0)),
        "latest_simulation_result": status.get("latest_simulation_result"),

        "updated_at":            status.get("updated_at"),
        "note":                  status.get("note", ""),
        # Polling configuration passed to the template for use by JS.
        "poll_endpoint":         "/api/v1/monitoring/status",
        "poll_interval_ms":      15000,   # 15 s default
        "poll_min_interval_ms":  5000,    # 5 s floor — enforced in JS
        "poll_max_backoff_ms":   120000,  # 2 min ceiling after failures
    }
    capture_status = capture_status or {
        "enabled": False, "source": "scapy", "state": "disabled",
        "packet_count": 0, "dropped_metadata_count": 0,
    }
    base["capture"] = {
        **capture_status,
        "source_display": "Simulated capture" if capture_status.get("source") == "fake" else "Live capture",
        "interfaces": tuple(interfaces),
    }
    base["flow_processing"] = flow_status or {
        "metadata_records_drained": 0,
        "metadata_records_processed": 0,
        "metadata_processing_failures": 0,
        "active_flow_count": 0,
        "completed_flow_count": 0,
        "completed_flow_eviction_count": 0,
        "feature_vectors_created": 0,
        "incompatible_flow_count": 0,
        "last_processing_timestamp": None,
        "last_flow_processing_error_category": None,
        "latest_completed_flow": None,
    }
    base["live_flow_evaluation"] = evaluation_status or {
        "evaluation_request_count": 0,
        "flows_considered_count": 0,
        "flows_skipped_already_evaluated_count": 0,
        "evaluation_incompatible_flow_count": 0,
        "successful_live_inference_count": 0,
        "failed_live_inference_count": 0,
        "successful_live_policy_count": 0,
        "failed_live_policy_count": 0,
        "live_recommendation_count": 0,
        "retained_evaluation_count": 0,
        "evaluation_eviction_count": 0,
        "eligible_flow_count": 0,
        "latest_live_evaluation": None,
        "recent_live_evaluations": (),
    }
    return base

def build_history_list_view_model(records: list, total_count: int, page: int, page_size: int, metrics: dict) -> dict:
    """Build view model for the simulation history list page."""
    base = get_base_view_model("Simulation History")
    base["active_nav_key"] = "monitoring"
    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": "Monitoring", "url": "/dashboard/monitoring"},
        {"name": "History", "url": None},
    ]

    # Enrich records for display
    enriched_records = []
    for r in records:
        lbl, cls = monitoring_state_display(r.state)
        enriched_records.append({
            "cycle_id": r.cycle_id,
            "state_display": lbl,
            "state_badge_class": cls,
            "completed_at": r.completed_at,
            "predicted_canonical_label": r.predicted_canonical_label,
            "confidence_score": r.confidence_score,
            "risk_score": r.risk_score,
            "alert_recommended": r.alert_recommended,
            "proposed_severity": r.proposed_severity,
            "inference_status": r.inference_status,
            "policy_status": r.policy_status
        })

    base["history"] = {
        "records": enriched_records,
        "total_count": total_count,
        "page": page,
        "page_size": page_size,
        "has_next": (page * page_size) < total_count,
        "has_prev": page > 1,
        "metrics": metrics
    }
    return base

def build_history_detail_view_model(record) -> dict:
    """Build view model for a single simulation history record."""
    base = get_base_view_model("Simulation Detail")
    base["active_nav_key"] = "monitoring"
    base["breadcrumbs"] = [
        {"name": "Home", "url": "/dashboard/"},
        {"name": "Monitoring", "url": "/dashboard/monitoring"},
        {"name": "History", "url": "/dashboard/monitoring/history"},
        {"name": record.cycle_id, "url": None},
    ]

    lbl, cls = monitoring_state_display(record.state)

    base["record"] = {
        "cycle_id": record.cycle_id,
        "state_display": lbl,
        "state_badge_class": cls,
        "started_at": record.started_at,
        "completed_at": record.completed_at,
        "duration_ms": record.duration_ms,
        "simulated": record.simulated,
        "alert_persisted": record.alert_persisted,
        "notification_sent": record.notification_sent,
        "blocking_executed": record.blocking_executed,
        "inference_status": record.inference_status,
        "predicted_canonical_label": record.predicted_canonical_label,
        "confidence_score": record.confidence_score,
        "risk_score": record.risk_score,
        "model_version": record.model_version,
        "policy_status": record.policy_status,
        "alert_recommended": record.alert_recommended,
        "proposed_alert_type": record.proposed_alert_type,
        "proposed_severity": record.proposed_severity,
        "reason_code": record.reason_code,
        "policy_version": record.policy_version,
        "safe_error_category": record.safe_error_category
    }
    return base
