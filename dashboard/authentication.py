from flask import (
    current_app, g, jsonify, redirect, render_template, request, session, url_for,
)

from auth.models import Permission

MUTATION_PERMISSIONS = {
    "dashboard.infer_flow": Permission.FLOW_EVALUATE,
    "dashboard.infer_flows": Permission.FLOW_EVALUATE,
    "dashboard.create_alert_from_recommendation": Permission.ALERT_CREATE,
    "dashboard.capture_interfaces_refresh": Permission.MONITORING_CONTROL,
    "dashboard.capture_devices_refresh": Permission.MONITORING_CONTROL,
    "dashboard.capture_start": Permission.MONITORING_CONTROL,
    "dashboard.capture_stop": Permission.MONITORING_CONTROL,
    "dashboard.process_captured_metadata": Permission.FLOW_PROCESS,
    "dashboard.evaluate_live_metadata_flows": Permission.FLOW_EVALUATE,
    "dashboard.create_live_flow_recommendation_alert": Permission.ALERT_CREATE,
    "dashboard.monitoring_simulate": Permission.FLOW_EVALUATE,
    "dashboard.apply_defensive_action": Permission.DEFENSIVE_ACTION_APPLY,
    "dashboard.remove_defensive_action": Permission.DEFENSIVE_ACTION_REMOVE,
    "dashboard.alert_notification": Permission.NOTIFICATION_SEND,
    "dashboard.alert_acknowledge": Permission.ALERT_LIFECYCLE_MANAGE,
    "dashboard.alert_confirm_action": Permission.ALERT_LIFECYCLE_MANAGE,
    "dashboard.alert_terminal_action": Permission.ALERT_LIFECYCLE_MANAGE,
}


def install_authentication(app):
    def audit_denial(outcome, category):
        try:
            deps = current_app.extensions["dependencies"]
            user = getattr(g, "current_user", None)
            deps.security_audit_service.record(
                request.endpoint or "unknown", "authorization",
                outcome=outcome,
                actor_public_user_id=user.public_user_id if user else None,
                request_id=getattr(g, "request_id", None),
                safe_error_category=category,
            )
        except Exception:
            app.logger.error("Security audit write failed safely.")

    @app.before_request
    def load_and_authorize_user():
        if not app.config.get("AUTHENTICATION_REQUIRED", True):
            g.current_user = None
            return None
        deps = current_app.extensions.get("dependencies")
        public_id = session.get("authenticated_user_id")
        g.current_user = (
            deps.user_account_service.get_active(public_id)
            if deps and public_id else None
        )
        endpoint = request.endpoint or ""
        if endpoint in {"auth.login_page", "auth.login_submit", "dashboard.static"}:
            return None
        is_dashboard = endpoint.startswith("dashboard.")
        is_monitoring_api = endpoint == "monitoring.get_monitoring_status"
        if not is_dashboard and not is_monitoring_api and endpoint != "auth.logout":
            return None
        if not g.current_user:
            audit_denial("denied", "authentication_required")
            if is_monitoring_api:
                return jsonify({"error": {"code": "AUTHENTICATION_REQUIRED"}}), 401
            next_path = request.full_path.rstrip("?")
            return redirect(url_for("auth.login_page", next=next_path), code=303)
        permission = MUTATION_PERMISSIONS.get(
            endpoint, Permission.DASHBOARD_VIEW
        )
        if endpoint == "auth.logout":
            permission = Permission.DASHBOARD_VIEW
        if not deps.authorization_service.allowed(g.current_user, permission):
            audit_denial("denied", "permission_denied")
            if is_monitoring_api:
                return jsonify({"error": {"code": "FORBIDDEN"}}), 403
            return render_template("dashboard/auth/forbidden.html"), 403

    @app.context_processor
    def inject_current_user():
        deps = current_app.extensions.get("dependencies")
        user = getattr(g, "current_user", None)
        return {
            "current_user": user,
            "has_permission": lambda permission: bool(
                not app.config.get("AUTHENTICATION_REQUIRED", True)
                or (deps and deps.authorization_service.allowed(user, permission))
            ),
        }

    @app.after_request
    def audit_sensitive_action(response):
        if (
            app.config.get("AUTHENTICATION_REQUIRED", True)
            and request.method == "POST"
            and request.endpoint in MUTATION_PERMISSIONS
            and getattr(g, "current_user", None)
        ):
            try:
                deps = current_app.extensions["dependencies"]
                target_id = next(iter((request.view_args or {}).values()), None)
                deps.security_audit_service.record(
                    request.endpoint, "dashboard_action",
                    str(target_id) if target_id is not None else None,
                    "success" if response.status_code < 400 else "failed",
                    g.current_user.public_user_id,
                    getattr(g, "request_id", None),
                    None if response.status_code < 400 else "request_rejected",
                )
            except Exception:
                app.logger.error("Security audit write failed safely.")
        return response
