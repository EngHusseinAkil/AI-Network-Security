"""
Dashboard routes and blueprint registration.
"""
import logging
import ipaddress
import socket
from flask import Blueprint, render_template, current_app, abort, request, flash, redirect, url_for, g
from dashboard.view_models import (
    get_base_view_model,
    build_health_view_model,
    build_health_overview_view_model,
    build_monitoring_view_model,
)

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint(
    'dashboard',
    __name__,
    template_folder='templates',
    static_folder='static/dashboard',
    static_url_path='/static',
)
from network.features import FLOW_FEATURE_ORDER, normalize_direction, normalize_protocol

from dashboard.security import generate_csrf_token


def _presentation_local_device():
    """Return known local endpoint identity without inventing a hostname."""
    from network.interfaces import get_active_interfaces
    interfaces = get_active_interfaces()
    ips = {ip for iface in interfaces for ip in (iface.ip_addresses or []) if ip}
    mac = next((iface.mac_address for iface in interfaces
                if iface.mac_address and "**" not in iface.mac_address
                and iface.mac_address.replace(":", "").replace("-", "") != "0" * 12), None)
    ip = next(iter(ips), None)
    name = socket.getfqdn(ip) if ip else None
    return ips, ip, (name if name and name != ip else None), mac, interfaces


def _flow_associated_with_local_device(flow, local_ips, local_network):
    endpoints = {flow.get("source_ip"), flow.get("destination_ip")} if flow else set()
    endpoints.discard(None)
    if not endpoints:
        return True  # Legacy/fake flows have no endpoint sidecar.
    if endpoints & local_ips:
        return True
    if local_network:
        try:
            network = ipaddress.ip_network(local_network, strict=False)
            return any(ipaddress.ip_address(value) in network for value in endpoints)
        except ValueError:
            pass
    return False


def _select_presentation_evaluation(status, flows, device_ip=None):
    """Select latest meaningful local traffic, never based on prediction/risk."""
    local_ips, _, _, _, _ = _presentation_local_device()
    local_network = current_app.config.get("LIVE_LOCAL_NETWORK_CIDR")
    candidates = []
    for item in reversed(status.get("recent_live_evaluations", ())):
        flow = flows.get_completed_flow(item.get("flow_id"))
        if flow and (not device_ip or device_ip in {
                flow.get("source_ip"), flow.get("destination_ip")
        }) and _flow_associated_with_local_device(flow, local_ips, local_network):
            candidates.append((item, flow))
    meaningful = next(((item, flow) for item, flow in candidates
                       if flow.get("packet_count", 0) > 1), None)
    return meaningful or (candidates[0] if candidates else (None, None))


def _select_device_evaluation(status, flows, device_ip):
    """Select the latest meaningful compatible evaluation for one device.

    The order is temporal only.  Risk, prediction, and confidence never
    influence which result represents a device.
    """
    candidates = []
    for item in reversed(status.get("recent_live_evaluations", ())):
        if not item.get("feature_compatible"):
            continue
        flow = flows.get_completed_flow(item.get("flow_id"))
        if not flow or device_ip not in {flow.get("source_ip"), flow.get("destination_ip")}:
            continue
        candidates.append((item, flow))
    return (next((pair for pair in candidates if pair[1].get("packet_count", 0) > 1), None)
            or (candidates[0] if candidates else (None, None)))

@dashboard_bp.context_processor
def inject_csrf():
    """Injects the CSRF token into all dashboard templates."""
    return {
        "csrf_token": generate_csrf_token(),
        "demo_mode": bool(current_app.config.get("DEMO_MODE")),
    }

@dashboard_bp.route('/')
def index():
    """Render the dashboard overview foundation."""
    view_model = get_base_view_model("Overview")
    # Enable health link on overview page
    for item in view_model["nav_items"]:
        if item["key"] == "health":
            item["enabled"] = True
            item["url"] = "/dashboard/health"
    return render_template('dashboard/index.html', **view_model)

def _get_health_service():
    deps = current_app.extensions.get('dependencies')
    if not deps or not hasattr(deps, 'dashboard_health_service'):
        logger.error("DashboardHealthService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.dashboard_health_service

@dashboard_bp.route('/health')
def health_overview():
    """Render the combined health overview page."""
    svc = _get_health_service()
    system_health = svc.get_system_health()
    ai_health = svc.get_ai_health()
    backend_health = svc.get_backend_health()

    vm = build_health_overview_view_model(system_health, ai_health, backend_health)
    return render_template('dashboard/health/index.html', **vm)

@dashboard_bp.route('/health/system')
def health_system():
    """Render system health details."""
    svc = _get_health_service()
    data = svc.get_system_health()
    vm = build_health_view_model("System Health", data, "System Core")
    return render_template('dashboard/health/detail.html', **vm)

@dashboard_bp.route('/health/ai')
def health_ai():
    """Render AI health details."""
    svc = _get_health_service()
    data = svc.get_ai_health()
    vm = build_health_view_model("AI Engine Health", data, "AI Engine")
    return render_template('dashboard/health/detail.html', **vm)

@dashboard_bp.route('/health/backend')
def health_backend():
    """Render backend health details."""
    svc = _get_health_service()
    data = svc.get_backend_health()
    vm = build_health_view_model("Backend APIs Health", data, "Backend APIs")
    return render_template('dashboard/health/detail.html', **vm)

def _get_model_service():
    deps = current_app.extensions.get('dependencies')
    if not deps or not hasattr(deps, 'dashboard_model_service'):
        logger.error("DashboardModelService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.dashboard_model_service

def _get_data_service():
    deps = current_app.extensions.get('dependencies')
    if not deps or not hasattr(deps, 'dashboard_data_service'):
        logger.error("DashboardDataService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.dashboard_data_service

@dashboard_bp.route('/models')
def models_overview():
    svc = _get_model_service()
    data = svc.get_model_overview()
    from dashboard.view_models import build_model_overview_view_model
    vm = build_model_overview_view_model(data)
    return render_template('dashboard/models/index.html', **vm)

@dashboard_bp.route('/devices')
def devices_list():
    from flask import request
    svc = _get_data_service()
    page = request.args.get('page', 1, type=int)
    size = request.args.get('page_size', 20, type=int)
    data = svc.get_devices(page=page, size=size)
    from dashboard.view_models import build_collection_view_model
    vm = build_collection_view_model("Devices", "devices", data, "/dashboard/devices")
    return render_template('dashboard/devices/index.html', **vm)

@dashboard_bp.route('/devices/<device_id>')
def devices_detail(device_id):
    svc = _get_data_service()
    data = svc.get_device(device_id)
    if not data["item"]:
        abort(404)
    from dashboard.view_models import build_detail_view_model
    vm = build_detail_view_model(f"Device {device_id}", "devices", data, "/dashboard/devices")
    return render_template('dashboard/devices/detail.html', **vm)

@dashboard_bp.route('/traffic')
def traffic_list():
    from flask import request
    svc = _get_data_service()
    page = request.args.get('page', 1, type=int)
    size = request.args.get('page_size', 20, type=int)
    data = svc.get_traffic(page=page, size=size)
    from dashboard.view_models import build_collection_view_model
    vm = build_collection_view_model("Traffic", "traffic", data, "/dashboard/traffic")
    return render_template('dashboard/traffic/index.html', **vm)

@dashboard_bp.route('/traffic/<int:record_id>')
def traffic_detail(record_id):
    svc = _get_data_service()
    data = svc.get_traffic_record(record_id)
    if not data["item"]:
        abort(404)
    from dashboard.view_models import build_detail_view_model
    vm = build_detail_view_model(f"Traffic Record {record_id}", "traffic", data, "/dashboard/traffic")
    return render_template('dashboard/traffic/detail.html', **vm)

@dashboard_bp.route('/threats')
def threats_list():
    from flask import request
    svc = _get_data_service()
    page = request.args.get('page', 1, type=int)
    size = request.args.get('page_size', 20, type=int)
    data = svc.get_threats(page=page, size=size)
    from dashboard.view_models import build_collection_view_model
    vm = build_collection_view_model("Threats", "threats", data, "/dashboard/threats")
    return render_template('dashboard/threats/index.html', **vm)

@dashboard_bp.route('/threats/<threat_id>')
def threats_detail(threat_id):
    """Render threat detail."""
    svc = current_app.extensions['dependencies'].dashboard_data_service
    data = svc.get_threat(threat_id)
    if not data.get("item"):
        abort(404)
    from dashboard.view_models import build_detail_view_model
    vm = build_detail_view_model(f"Threat {threat_id}", "threats", data, "/dashboard/threats")
    return render_template('dashboard/threats/detail.html', **vm)

from dashboard.security import csrf_protect
from dashboard.view_models import build_inference_view_model
from dashboard.form_parsing import parse_flow_form_fields
import json
from flask import request
from backend.errors.exceptions import ServiceUnavailableError

def _get_inference_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_inference_service"):
        logger.error("DashboardInferenceService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.dashboard_inference_service

def _get_alert_evaluation_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_alert_evaluation_service"):
        logger.error("DashboardAlertEvaluationService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.dashboard_alert_evaluation_service

def _get_alert_creation_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_alert_creation_service"):
        logger.error("DashboardAlertCreationService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.dashboard_alert_creation_service

@dashboard_bp.route('/inference', methods=['GET'])
def inference_index():
    """Render the inference form page."""
    vm = build_inference_view_model()
    return render_template('dashboard/inference/index.html', **vm)

@dashboard_bp.route('/inference/flow', methods=['POST'])
@csrf_protect
def inference_single_flow():
    """Handle single flow inference submission."""
    from backend.schemas.inference import validate_single_flow_inference_request
    from utils.exceptions import ValidationError

    # --- Step 1: strict type-aware form parsing ---
    try:
        features = parse_flow_form_fields(request.form)
    except ValueError as e:
        vm = build_inference_view_model(
            form_data=request.form,
            error=str(e),
        )
        return render_template('dashboard/inference/index.html', **vm), 400

    svc = _get_inference_service()

    # --- Step 2: backend schema validation (range / encoding checks) ---
    try:
        validate_single_flow_inference_request(features)
    except ValidationError as e:
        vm = build_inference_view_model(form_data=request.form, error=str(e))
        return render_template('dashboard/inference/index.html', **vm), 400

    # --- Step 3: inference ---
    try:
        data = svc.predict_flow(features)
    except ServiceUnavailableError as e:
        vm = build_inference_view_model(form_data=request.form, error=str(e))
        return render_template('dashboard/inference/index.html', **vm), 503
    except Exception:
        logger.exception("Unexpected error in dashboard single flow inference.")
        vm = build_inference_view_model(
            form_data=request.form,
            error="Inference failed due to an unexpected server error.",
        )
        return render_template('dashboard/inference/index.html', **vm), 500

    if data.get("error"):
        error_msg = data["error"]
        status = 503 if "unavailable" in error_msg else 400
        vm = build_inference_view_model(form_data=request.form, error=error_msg)
        return render_template('dashboard/inference/index.html', **vm), status

    # --- Step 4: Evaluate single inference policy ---
    try:
        eval_svc = _get_alert_evaluation_service()
        recommendation = eval_svc.evaluate_single_inference(data.get("result", {}))

        if recommendation.get("available") and recommendation.get("should_create_alert"):
            creation_svc = _get_alert_creation_service()
            from dashboard.security import generate_csrf_token
            csrf = generate_csrf_token()
            token = creation_svc.generate_recommendation_token(
                recommendation=recommendation,
                inference_result=data.get("result", {}),
                session_csrf=csrf
            )
            recommendation["recommendation_token"] = token

    except Exception as e:
        logger.exception("Policy evaluation failed safely: %s", str(e))
        recommendation = {"available": False, "error": "Policy evaluation unavailable"}

    vm = build_inference_view_model(
        form_data=request.form,
        result_data={
            "single": data.get("result"),
            "recommendation": recommendation
        },
    )
    return render_template('dashboard/inference/index.html', **vm)

@dashboard_bp.route('/inference/flows', methods=['POST'])
@csrf_protect
def inference_batch_flows():
    """Handle batch flow inference submission."""
    batch_json_str = request.form.get("batch_data")
    if not batch_json_str:
        vm = build_inference_view_model(form_data=request.form, error="Missing batch data.")
        return render_template('dashboard/inference/index.html', **vm), 400

    try:
        payload = json.loads(batch_json_str)
    except json.JSONDecodeError:
        vm = build_inference_view_model(form_data=request.form, error="Malformed JSON data.")
        return render_template('dashboard/inference/index.html', **vm), 400

    svc = _get_inference_service()

    try:
        # Pre-validate against the strict schema
        from backend.schemas.inference import validate_batch_flow_inference_request
        from utils.exceptions import ValidationError
        try:
            max_batch = current_app.config.get('MAX_INFERENCE_BATCH_SIZE', 100)
            safe_batch = validate_batch_flow_inference_request(payload, max_batch_size=max_batch)
        except ValidationError as e:
            vm = build_inference_view_model(form_data=request.form, error=str(e))
            return render_template('dashboard/inference/index.html', **vm), 400

        data = svc.predict_flows(safe_batch)

        if data.get("error"):
            vm = build_inference_view_model(form_data=request.form, error=data["error"])
            return render_template('dashboard/inference/index.html', **vm), 503 if "unavailable" in data["error"] else 400

        # --- Step 4: Evaluate batch inference policy (deferred) ---
        try:
            eval_svc = _get_alert_evaluation_service()
            recommendation = eval_svc.evaluate_batch_inference(data.get("result", {}))
        except Exception as e:
            logger.exception("Batch policy evaluation failed safely: %s", str(e))
            recommendation = {"available": False, "error": "Policy evaluation unavailable"}

        vm = build_inference_view_model(
            result_data={
                "batch": data.get("result"),
                "recommendation": recommendation
            }
        )
        return render_template('dashboard/inference/index.html', **vm)

    except ServiceUnavailableError as e:
        logger.warning(f"Batch flow prediction unavailable: {e.message}")
        vm = build_inference_view_model(
            form_data=request.form,
            error="The model or engine is currently unavailable.",
        )
        return render_template('dashboard/inference/index.html', **vm), 503
    except ValueError as e:
        logger.warning(f"Batch flow validation error: {e}")
        vm = build_inference_view_model(form_data=request.form, error=str(e))
        return render_template('dashboard/inference/index.html', **vm), 400
    except Exception as e:
        from backend.errors.exceptions import RequestValidationError
        if isinstance(e, RequestValidationError):
            logger.warning(f"Batch flow request validation error: {e}")
            vm = build_inference_view_model(form_data=request.form, error=str(e))
            return render_template('dashboard/inference/index.html', **vm), 400
        logger.exception("Unexpected error in batch flow inference")
        vm = build_inference_view_model(
            form_data=request.form,
            error="An unexpected server error occurred.",
        )
        return render_template('dashboard/inference/index.html', **vm), 500

@dashboard_bp.route('/alerts/from-recommendation', methods=['POST'])
@csrf_protect
def create_alert_from_recommendation():
    """Explicitly creates an alert from a recommendation token.

    Replay / duplicate policy (deterministic):
    * If the deduplication lookup finds an existing alert, flash a fixed warning
      and return 303 See Other to the existing alert's detail page.
    * If a concurrent database uniqueness constraint fires without a resolvable ID,
      return 409 Conflict — the caller may retry via a fresh GET.
    * Exactly one alert is persisted in both cases.
    """
    token = request.form.get("recommendation_token")
    if not token:
        abort(400, "Missing recommendation token.")

    try:
        creation_svc = _get_alert_creation_service()
        from dashboard.security import generate_csrf_token
        csrf = generate_csrf_token()

        public_id = creation_svc.create_alert_from_token(token, csrf)
        flash("Alert successfully created from policy recommendation.", "success")
        # 303 See Other: correct status for POST→GET redirect (prevents browser re-POST on refresh)
        return redirect(url_for('dashboard.alert_detail', alert_id=public_id), 303)

    except Exception as e:
        from utils.exceptions import ConflictError, ApplicationError
        if isinstance(e, ConflictError):
            dup_id = e.details.get("duplicate_id") if e.details else None
            if dup_id:
                # Known duplicate: redirect to existing alert with safe notice
                flash("This alert was already created.", "warning")
                return redirect(url_for('dashboard.alert_detail', alert_id=dup_id), 303)
            # Unknown duplicate (concurrent constraint): unresolvable, return 409
            logger.warning("Unresolvable duplicate constraint during alert creation")
            abort(409, "Alert could not be created due to a concurrent conflict.")
        elif isinstance(e, ApplicationError):
            logger.warning("Invalid alert creation request: %s", str(e))
            flash(f"Could not create alert: {e.message}", "error")
        else:
            logger.exception("Failed to create alert from recommendation: %s", str(e))
            flash("Failed to create alert due to an internal error or expired token.", "error")

        return redirect(url_for('dashboard.inference_index'), 303)


# ---------------------------------------------------------------------------
# Monitoring page
# ---------------------------------------------------------------------------

def _get_monitoring_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "monitoring_service"):
        logger.error("MonitoringStateService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.monitoring_service


def _get_dashboard_capture_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_capture_service"):
        abort(503, description="Capture dependencies unavailable.")
    return deps.dashboard_capture_service


def _get_dashboard_flow_processing_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_flow_processing_service"):
        abort(503, description="Flow processing dependencies unavailable.")
    return deps.dashboard_flow_processing_service


def _get_dashboard_live_flow_evaluation_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_live_flow_evaluation_service"):
        abort(503, description="Live flow evaluation dependencies unavailable.")
    return deps.dashboard_live_flow_evaluation_service


@dashboard_bp.route("/monitoring", methods=["GET"])
def monitoring_overview():
    """Render the read-only monitoring state page."""
    svc = _get_monitoring_service()
    status = svc.get_status()
    capture = _get_dashboard_capture_service()
    flows = _get_dashboard_flow_processing_service()
    evaluations = _get_dashboard_live_flow_evaluation_service()
    capture_snapshot = capture.status()
    if (capture_snapshot.get("enabled") and capture_snapshot.get("state") == "stopped"
            and not capture_snapshot.get("devices")):
        try:
            capture.refresh_devices()
            capture_snapshot["devices"] = capture.devices()
        except Exception:
            logger.info("Connected-device discovery unavailable during page render.")
    vm = build_monitoring_view_model(
        status, capture_snapshot, capture.interfaces(), flows.status(),
        evaluations.presentation(generate_csrf_token()),
    )
    return render_template("dashboard/monitoring/index.html", **vm)


@dashboard_bp.route("/presentation-demo", methods=["GET"])
def presentation_demo():
    """Render the projection-friendly, read-only presentation surface."""
    evaluations = _get_dashboard_live_flow_evaluation_service()
    flows = _get_dashboard_flow_processing_service()
    capture = _get_dashboard_capture_service()
    status = evaluations.presentation(generate_csrf_token())
    requested_device_ip = request.args.get("device_ip", "").strip() or None
    selected_devices = [item for item in capture.devices() if item.get("selected")]
    cards = []
    for device in selected_devices:
        evaluation, flow = _select_device_evaluation(status, flows, device["ip_address"])
        card = {
            "device": device,
            "evaluation": evaluation,
            "flow": flow,
            "waiting": evaluation is None or flow is None,
        }
        cards.append(card)

    detail_card = next((card for card in cards
                        if card["device"]["ip_address"] == requested_device_ip), None)
    if detail_card is None:
        detail_card = next((card for card in cards if not card["waiting"]), None)
    latest = detail_card["evaluation"] if detail_card else None
    flow = detail_card["flow"] if detail_card else None
    detail_device = detail_card["device"] if detail_card else {}
    features = None
    if flow:
        feature_values = {
            "duration": flow.get("duration_seconds"),
            "packet_count": flow.get("packet_count"),
            "byte_count": flow.get("total_bytes"),
            "min_packet_size": flow.get("minimum_packet_length"),
            "max_packet_size": flow.get("maximum_packet_length"),
            "avg_packet_size": flow.get("mean_packet_length"),
            "protocol_enc": normalize_protocol(flow.get("protocol", "")),
            "direction_enc": normalize_direction(flow.get("direction", "")),
        }
        features = [(name, feature_values[name]) for name in FLOW_FEATURE_ORDER]

    presentation = {
        "evaluation": latest,
        "flow": flow,
        "features": features,
        "class_probabilities": None,
        "empty": not cards,
        "recommendation_token": (latest and next(
            (item.get("recommendation_token") for item in status.get("recent_live_evaluations", ())
             if item.get("evaluation_id") == latest.get("evaluation_id")), None)),
        "monitored_devices": selected_devices,
        "device_cards": cards,
        "selected_device_ip": requested_device_ip or detail_device.get("ip_address"),
        "evaluated_device_count": sum(1 for card in cards if not card["waiting"]),
        "waiting_device_count": sum(1 for card in cards if card["waiting"]),
        "monitored_device": {
            "ip": detail_device.get("ip_address"),
            "name": detail_device.get("hostname"),
            "mac": detail_device.get("mac_address"),
        },
        "flow_selection_rule": "Most recent compatible evaluation associated with each device; prefer packet_count > 1, otherwise most recent by evaluation order.",
    }

    vm = get_base_view_model("Presentation Demo")
    vm.update({
        "active_nav_key": "monitoring",
        "breadcrumbs": [],
        "presentation": presentation,
        "operator_label": getattr(g, "current_user", None).login_label if getattr(g, "current_user", None) else "demooperator",
        "operator_role": getattr(g, "current_user", None).role.lower() if getattr(g, "current_user", None) else "operator",
    })
    return render_template("dashboard/monitoring/presentation_demo.html", **vm)


def _capture_failure_status(exc):
    from network.capture_exceptions import (
        CaptureAlreadyRunningError, CaptureDisabledError, CaptureInvalidInterfaceError,
        CaptureMissingDependencyError, CaptureNotRunningError, CapturePermissionError,
        CaptureSourceUnavailableError, CaptureStopTimeoutError,
    )
    if isinstance(exc, CaptureDisabledError):
        return 403
    if isinstance(exc, CaptureInvalidInterfaceError):
        return 400
    if isinstance(exc, (CaptureAlreadyRunningError, CaptureNotRunningError)):
        return 409
    if isinstance(exc, (CaptureMissingDependencyError, CapturePermissionError,
                        CaptureSourceUnavailableError, CaptureStopTimeoutError)):
        return 503
    return 503


@dashboard_bp.route("/monitoring/capture/interfaces/refresh", methods=["POST"])
@csrf_protect
def capture_interfaces_refresh():
    try:
        capture = _get_dashboard_capture_service()
        if hasattr(capture, "refresh_hotspot"):
            capture.refresh_hotspot()
        else:
            capture.refresh_interfaces()
    except Exception as exc:
        abort(_capture_failure_status(exc), description="Interface discovery unavailable.")
    flash("Network interfaces refreshed successfully.", "success")
    return redirect(url_for("dashboard.monitoring_overview"), code=303)


@dashboard_bp.route("/monitoring/capture/devices/refresh", methods=["POST"])
@csrf_protect
def capture_devices_refresh():
    try:
        _get_dashboard_capture_service().refresh_devices()
    except Exception:
        logger.exception("Connected-device discovery failed safely.")
        abort(503, description="Connected-device discovery unavailable.")
    flash("Connected devices refreshed successfully.", "success")
    return redirect(url_for("dashboard.monitoring_overview"), code=303)


@dashboard_bp.route("/monitoring/capture/start", methods=["POST"])
@csrf_protect
def capture_start():
    try:
        capture = _get_dashboard_capture_service()
        if request.form.get("interface_key"):
            # Admin/debug compatibility path; the normal UI never posts this.
            capture.start(request.form.get("interface_key"))
        else:
            capture.start_monitoring(request.form.getlist("selected_device_ip"))
    except Exception as exc:
        abort(_capture_failure_status(exc), description="Capture could not be started.")
    return redirect(url_for("dashboard.monitoring_overview"), code=303)


@dashboard_bp.route("/monitoring/capture/stop", methods=["POST"])
@csrf_protect
def capture_stop():
    try:
        _get_dashboard_capture_service().stop()
    except Exception as exc:
        # The capture worker may have completed normally between the page
        # render and this POST (for example, due to a configured safety
        # limit).  Preserve the service/API's 409 semantics while making this
        # normal dashboard race idempotent and presentation-safe.
        from network.capture_exceptions import CaptureNotRunningError
        if isinstance(exc, CaptureNotRunningError):
            flash("Capture is already stopped.", "info")
            return redirect(url_for("dashboard.monitoring_overview"), code=303)
        abort(_capture_failure_status(exc), description="Capture could not be stopped.")
    return redirect(url_for("dashboard.monitoring_overview"), code=303)


@dashboard_bp.route("/monitoring/flows/process", methods=["POST"])
@csrf_protect
def process_captured_metadata():
    try:
        _get_dashboard_flow_processing_service().process()
    except Exception:
        logger.exception("Explicit captured metadata processing failed.")
        abort(503, description="Captured metadata processing unavailable.")
    flash("Captured metadata processed successfully.", "success")
    return redirect(url_for("dashboard.monitoring_overview"), code=303)


@dashboard_bp.route("/monitoring/flows/evaluate", methods=["POST"])
@csrf_protect
def evaluate_live_metadata_flows():
    try:
        _get_dashboard_live_flow_evaluation_service().evaluate()
    except Exception:
        logger.exception("Explicit live metadata-flow evaluation failed safely.")
        abort(503, description="Live metadata-flow evaluation unavailable.")
    flash("Live metadata-flow evaluation completed successfully.", "success")
    return redirect(url_for("dashboard.monitoring_overview"), code=303)


@dashboard_bp.route(
    "/monitoring/flows/evaluations/<evaluation_id>/alerts", methods=["POST"]
)
@csrf_protect
def create_live_flow_recommendation_alert(evaluation_id):
    from backend.services.live_flow_alert_creation_service import LiveFlowAlertError

    allowed_fields = {"csrf_token", "recommendation_token"}
    if set(request.form) - allowed_fields:
        abort(400, description="Unexpected alert creation fields.")
    token = request.form.get("recommendation_token", "")
    if not token:
        abort(400, description="Recommendation token is required.")
    try:
        alert_id, replayed = _get_dashboard_live_flow_evaluation_service().create_alert(
            evaluation_id, token, generate_csrf_token()
        )
    except LiveFlowAlertError as exc:
        abort(exc.status_code, description=str(exc))
    except Exception:
        logger.exception("Explicit live metadata-flow alert creation failed safely.")
        abort(503, description="Alert creation unavailable.")
    if replayed:
        flash("This alert was already created.", "info")
    else:
        flash(
            "Alert successfully created from live metadata-flow recommendation.",
            "success",
        )
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id), code=303)

def _get_monitoring_simulation_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "monitoring_simulation_service"):
        logger.error("MonitoringSimulationService not found in application dependencies.")
        abort(503, description="Simulation dependencies unavailable.")
    return deps.monitoring_simulation_service


@dashboard_bp.route("/monitoring/simulate", methods=["POST"])
@csrf_protect
def monitoring_simulate():
    """Execute a simulated monitoring cycle."""
    from dashboard.form_parsing import parse_flow_form_fields

    try:
        features = parse_flow_form_fields(request.form)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("dashboard.monitoring_overview"))

    svc = _get_monitoring_simulation_service()

    try:
        result = svc.simulate_flow(features)

        if result.get("state") == "error":
            flash(f"Simulation failed: {result.get('safe_error_category')}", "error")
        else:
            flash("Simulation completed successfully.", "success")

    except Exception as e:
        logger.exception("Unexpected error in monitoring simulate route.")
        flash("An unexpected error occurred during simulation.", "error")

    return redirect(url_for("dashboard.monitoring_overview"))

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def _get_alert_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_alert_service"):
        logger.error("DashboardAlertService not found in application dependencies.")
        abort(503, description="Dashboard dependencies unavailable.")
    return deps.dashboard_alert_service


def _get_alert_notification_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_alert_notification_service"):
        abort(503, description="Notification dependencies unavailable.")
    return deps.dashboard_alert_notification_service


def _get_defensive_action_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "dashboard_defensive_action_service"):
        abort(503, description="Defensive action dependencies unavailable.")
    return deps.dashboard_defensive_action_service

@dashboard_bp.route("/alerts", methods=["GET"])
def alerts_list():
    """Render the paginated list of alerts."""
    svc = _get_alert_service()

    page = request.args.get("page", 1, type=int)
    size = request.args.get("page_size", 20, type=int)

    filters = {
        "status": request.args.get("status"),
        "severity": request.args.get("severity"),
        "alert_type": request.args.get("alert_type")
    }

    # Clean filters
    filters = {k: v for k, v in filters.items() if v}

    data = svc.get_alerts(page=page, size=size, filters=filters)

    if data.get("error"):
        abort(503, description=data["error"])

    from dashboard.view_models import get_base_view_model
    vm = get_base_view_model("Alerts")
    result = data["result"]
    vm["records"] = result["alerts"]
    vm["page"] = result["pagination"]["page"]
    vm["size"] = result["pagination"]["page_size"]
    vm["total"] = result["pagination"]["total_items"]
    vm["filters"] = filters
    vm["title"] = "Security Alerts"
    return render_template("dashboard/alerts/index.html", **vm)

@dashboard_bp.route("/alerts/<alert_id>", methods=["GET"])
def alert_detail(alert_id):
    """Render the alert detail page."""
    svc = _get_alert_service()
    data = svc.get_alert(alert_id)

    if data.get("status_code") == 404:
        abort(404)
    elif data.get("error"):
        abort(503, description=data["error"])

    from dashboard.view_models import get_base_view_model
    vm = get_base_view_model(f"Alert {alert_id}")
    vm["item"] = data["result"]
    try:
        vm["notification"] = _get_alert_notification_service().presentation(
            data["result"], generate_csrf_token()
        )
        vm["defense"] = _get_defensive_action_service().presentation(
            data["result"], generate_csrf_token()
        )
    except Exception:
        logger.exception("Alert notification history unavailable.")
        abort(503, description="Notification history unavailable.")
    return render_template("dashboard/alerts/detail.html", **vm)


@dashboard_bp.route("/alerts/<alert_id>/defensive-actions", methods=["POST"])
@csrf_protect
def apply_defensive_action(alert_id):
    from backend.services.defensive_action_service import DefensiveActionError

    if set(request.form) - {"csrf_token", "defensive_confirmation_token"}:
        abort(400, description="Unexpected defensive action fields.")
    token = request.form.get("defensive_confirmation_token", "")
    if not token:
        abort(400, description="Defensive confirmation token is required.")
    try:
        action, replayed = _get_defensive_action_service().apply(
            alert_id, token, generate_csrf_token()
        )
    except DefensiveActionError as exc:
        abort(exc.status_code, description=str(exc))
    except Exception:
        logger.error(
            "Defensive action request_id=%s alert_id=%s outcome=failed",
            getattr(g, "request_id", None), alert_id,
        )
        abort(503, description="Defensive action unavailable.")
    flash(
        "This defensive action request was already processed."
        if replayed else "Temporary defensive action applied successfully.",
        "info" if replayed else "success",
    )
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id), code=303)


@dashboard_bp.route(
    "/alerts/<alert_id>/defensive-actions/<action_id>/remove", methods=["POST"]
)
@csrf_protect
def remove_defensive_action(alert_id, action_id):
    from backend.services.defensive_action_service import DefensiveActionError

    if set(request.form) - {"csrf_token", "defensive_removal_token"}:
        abort(400, description="Unexpected defensive removal fields.")
    token = request.form.get("defensive_removal_token", "")
    if not token:
        abort(400, description="Defensive removal token is required.")
    try:
        action, replayed = _get_defensive_action_service().remove(
            alert_id, action_id, token, generate_csrf_token()
        )
    except DefensiveActionError as exc:
        abort(exc.status_code, description=str(exc))
    except Exception:
        logger.error(
            "Defensive removal request_id=%s alert_id=%s action_id=%s outcome=failed",
            getattr(g, "request_id", None), alert_id, action_id,
        )
        abort(503, description="Defensive action removal unavailable.")
    flash(
        "This removal request was already processed."
        if replayed else "Temporary defensive action removed successfully.",
        "info" if replayed else "success",
    )
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id), code=303)


@dashboard_bp.route("/alerts/<alert_id>/notifications", methods=["POST"])
@csrf_protect
def alert_notification(alert_id):
    from backend.services.alert_notification_service import AlertNotificationError

    if set(request.form) - {"csrf_token", "notification_request_token"}:
        abort(400, description="Unexpected notification fields.")
    token = request.form.get("notification_request_token", "")
    if not token:
        abort(400, description="Notification request token is required.")
    try:
        delivery, replayed = _get_alert_notification_service().notify(
            alert_id, token, generate_csrf_token()
        )
    except AlertNotificationError as exc:
        logger.info(
            "Notification request_id=%s alert_id=%s outcome=rejected category=%s",
            getattr(g, "request_id", None), alert_id, type(exc).__name__,
        )
        abort(exc.status_code, description=str(exc))
    except Exception:
        logger.error(
            "Notification request_id=%s alert_id=%s outcome=failed "
            "category=notification_unavailable",
            getattr(g, "request_id", None), alert_id,
        )
        abort(503, description="Notification delivery unavailable.")
    logger.info(
        "Notification request_id=%s alert_id=%s delivery_id=%s outcome=%s",
        getattr(g, "request_id", None), alert_id, delivery["delivery_id"],
        "replayed" if replayed else "sent",
    )
    flash(
        "This notification request was already processed."
        if replayed else "Alert notification sent successfully.",
        "info" if replayed else "success",
    )
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id), code=303)

@dashboard_bp.route("/alerts/<alert_id>/acknowledge", methods=["POST"])
@csrf_protect
def alert_acknowledge(alert_id):
    """Acknowledge an alert."""
    svc = _get_alert_service()

    # We don't read current_status from form, it's determined by the route (target_status="acknowledged")
    # Expected version is required for concurrency control
    try:
        expected_version = int(request.form.get("expected_version"))
    except (ValueError, TypeError):
        abort(400, description="Invalid or missing expected_version")

    data = svc.transition_alert(alert_id, "acknowledged", expected_version)

    if data.get("error"):
        status_code = data.get("status_code", 400)
        if status_code == 404:
            abort(404)
        else:
            abort(status_code, description=data["error"])

    from flask import flash, redirect, url_for
    flash("Alert successfully acknowledged.", "success")
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))

@dashboard_bp.route("/alerts/<alert_id>/<action>/confirm", methods=["GET"])
def alert_confirm_action(alert_id, action):
    """Render explicit confirmation page for terminal actions."""
    if action not in ("resolve", "dismiss"):
        abort(404)

    svc = _get_alert_service()
    data = svc.get_alert(alert_id)

    if data.get("status_code") == 404:
        abort(404)
    elif data.get("error"):
        abort(503, description=data["error"])

    from dashboard.view_models import get_base_view_model
    vm = get_base_view_model(f"Confirm {action.title()} Alert")
    vm["alert"] = data["result"]
    vm["action"] = action
    return render_template("dashboard/alerts/confirm.html", **vm)

@dashboard_bp.route("/alerts/<alert_id>/<action>", methods=["POST"])
@csrf_protect
def alert_terminal_action(alert_id, action):
    """Resolve or dismiss an alert."""
    if action not in ("resolve", "dismiss"):
        abort(404)

    # Check confirmation field
    confirm_val = request.form.get("confirm_action")
    if confirm_val != action:
        abort(400, description="Explicit confirmation required.")

    svc = _get_alert_service()

    try:
        expected_version = int(request.form.get("expected_version"))
    except (ValueError, TypeError):
        abort(400, description="Invalid or missing expected_version")

    target_status = "resolved" if action == "resolve" else "dismissed"
    data = svc.transition_alert(alert_id, target_status, expected_version)

    if data.get("error"):
        status_code = data.get("status_code", 400)
        if status_code == 404:
            abort(404)
        else:
            abort(status_code, description=data["error"])


    from flask import flash, redirect, url_for
    flash(f"Alert successfully {target_status}.", "success")
    return redirect(url_for("dashboard.alert_detail", alert_id=alert_id))

# ---------------------------------------------------------------------------
# Monitoring History and Exports
# ---------------------------------------------------------------------------

def _get_simulation_evaluation_report_service():
    deps = current_app.extensions.get("dependencies")
    if not deps or not hasattr(deps, "simulation_evaluation_report_service"):
        logger.error("SimulationEvaluationReportService not found in application dependencies.")
        abort(503, description="Simulation reporting dependencies unavailable.")
    return deps.simulation_evaluation_report_service

@dashboard_bp.route("/monitoring/history", methods=["GET"])
def monitoring_history_list():
    """Render the paginated simulation history."""
    svc = _get_monitoring_service()

    page = request.args.get("page", 1, type=int)
    size = request.args.get("page_size", 20, type=int)

    try:
        records, total_count = svc.list_simulation_history(page, size)
    except ValueError:
        abort(400, "Invalid pagination parameters.")

    report_svc = _get_simulation_evaluation_report_service()
    # Ensure metrics match the chronological snapshot
    chronological_snapshot = svc._get_history_snapshot_chronological()
    metrics = report_svc.get_summary_metrics(chronological_snapshot)

    from dashboard.view_models import build_history_list_view_model
    vm = build_history_list_view_model(records, total_count, page, size, metrics)
    return render_template("dashboard/monitoring/history.html", **vm)

@dashboard_bp.route("/monitoring/history/<cycle_id>", methods=["GET"])
def monitoring_history_detail(cycle_id):
    """Render details of a single simulation cycle."""
    svc = _get_monitoring_service()
    record = svc.get_simulation_cycle(cycle_id)
    if not record:
        abort(404)

    from dashboard.view_models import build_history_detail_view_model
    vm = build_history_detail_view_model(record)
    return render_template("dashboard/monitoring/history_detail.html", **vm)

@dashboard_bp.route("/monitoring/reports/simulation.json", methods=["GET"])
def monitoring_export_json():
    """Download simulation history JSON report."""
    report_svc = _get_simulation_evaluation_report_service()
    report_data = report_svc.generate_json_report()

    from flask import jsonify, make_response
    response = make_response(jsonify(report_data))
    response.headers["Content-Disposition"] = "attachment; filename=simulation-evaluation-report.json"
    return response

@dashboard_bp.route("/monitoring/reports/simulation.csv", methods=["GET"])
def monitoring_export_csv():
    """Download simulation history CSV report."""
    report_svc = _get_simulation_evaluation_report_service()
    csv_str = report_svc.generate_csv_report()

    from flask import Response
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=simulation-evaluation-report.csv"}
    )
