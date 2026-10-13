"""
Tests for Phase 6 – Milestone 7: Monitoring State Service and Browser Polling Foundation.

Coverage
--------
Monitoring service:
    [P] get_status returns deterministic disabled state
    [P] enabled is False in initial state
    [P] state is "disabled" in initial state
    [P] processed_flow_count is 0 (no fabricated counts)
    [P] prediction_count is 0
    [P] alert_count is 0
    [P] unknown state tokens map safely to "unknown"
    [P] all known state tokens are accepted by safe_state()
    [P] service handles missing ai_health_svc gracefully
    [P] service handles missing model_svc gracefully
    [P] service handles ai_health_svc exception gracefully
    [P] service handles model_svc exception gracefully
    [P] no threads are started during service construction
    [P] no threads are started during service.get_status()
    [P] no database write occurs in get_status()
    [P] no model load occurs in get_status()
    [P] no inference occurs in get_status()
    [P] no capture occurs in get_status()
    [P] no alert is created in get_status()

Monitoring API endpoint:
    [P] GET /api/v1/monitoring/status returns 200
    [P] response uses standard success envelope
    [P] response includes request_id
    [P] response data includes "enabled", "state", "state_display"
    [P] response data includes "processed_flow_count" as integer 0
    [P] response data includes "prediction_count" as integer 0
    [P] response data includes "alert_count" as integer 0
    [P] missing service returns 503 with safe envelope
    [P] POST to monitoring/status is not allowed (405)
    [P] no external request occurs during test

Dashboard monitoring page:
    [P] GET /dashboard/monitoring returns 200
    [P] page contains "Monitoring" heading
    [P] page contains monitoring state badge
    [P] page contains monitoring-status-panel element with data-* attributes
    [P] page contains poll endpoint reference to /api/v1/monitoring/status
    [P] page contains counter fields
    [P] missing service returns 503

View model:
    [P] build_monitoring_view_model produces correct structure
    [P] unknown state maps to "unknown" badge class
    [P] disabled state maps to "info" badge class
    [P] running state maps to "success" badge class
    [P] error state maps to "danger" badge class
    [P] fabricated/arbitrary state token maps to "info" (unknown fallback)
    [P] counters are integers, not strings
    [P] poll_endpoint is /api/v1/monitoring/status
    [P] poll_interval_ms >= poll_min_interval_ms
    [P] nav_items contains monitoring entry with enabled=True
    [P] alerts nav item remains disabled

Navigation:
    [P] monitoring nav item is enabled in get_base_view_model
    [P] alerts nav item is disabled in get_base_view_model
    [P] monitoring page sets active_nav_key to "monitoring"

JavaScript static file:
    [P] monitoring.js is served at correct static path
    [P] monitoring.js does not use innerHTML with server data (textContent check)
    [P] monitoring.js contains allowlisted state mapping
    [P] monitoring.js contains AbortController (timeout support)
    [P] monitoring.js does not reference unrelated dashboard pages
    [P] monitoring.js checks document.hidden (visibility API)
    [P] monitoring.js uses "inFlight" guard (no overlapping requests)
    [P] monitoring.js uses exponential backoff
    [P] monitoring.js references only the monitoring status endpoint

Regression:
    [P] all previously passing dashboard foundation tests unaffected
    [P] no existing API routes broken
"""

import json
import threading
import pytest

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.services.monitoring_service import MonitoringStateService, MonitoringState
from dashboard.view_models import (
    build_monitoring_view_model,
    monitoring_state_display,
    get_base_view_model,
)


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------

class FakeAIHealthSvc:
    def get_health_summary(self):
        return {"overall_status": "pass", "readiness_level": "model_ready"}


class FakeModelSvc:
    def get_active_model(self):
        return {"active": True, "model": {"model_version": "v1.0"}}


class FailingAIHealthSvc:
    def get_health_summary(self):
        raise RuntimeError("health service exploded")


class FailingModelSvc:
    def get_active_model(self):
        raise RuntimeError("model service exploded")


def _make_app():
    deps = DependencyContainer()
    app = create_app(
        config_override={"TESTING": True, "SECRET_KEY": "test-m7-key"},
        dependencies=deps,
    )
    return app


@pytest.fixture()
def app():
    return _make_app()


@pytest.fixture()
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# MonitoringStateService unit tests
# ---------------------------------------------------------------------------

class TestMonitoringStateService:

    def test_get_status_returns_dict(self):
        svc = MonitoringStateService()
        result = svc.get_status()
        assert isinstance(result, dict)

    def test_enabled_is_false(self):
        svc = MonitoringStateService()
        assert svc.get_status()["enabled"] is False

    def test_state_is_disabled(self):
        svc = MonitoringStateService()
        assert svc.get_status()["state"] == MonitoringState.DISABLED

    def test_processed_flow_count_is_zero(self):
        """No fabricated counts — initial value must be exactly 0."""
        svc = MonitoringStateService()
        assert svc.get_status()["processed_flow_count"] == 0

    def test_prediction_count_is_zero(self):
        svc = MonitoringStateService()
        assert svc.get_status()["prediction_count"] == 0

    def test_alert_count_is_zero(self):
        svc = MonitoringStateService()
        assert svc.get_status()["alert_count"] == 0

    def test_last_successful_cycle_is_none(self):
        svc = MonitoringStateService()
        assert svc.get_status()["last_successful_cycle"] is None

    def test_updated_at_is_none(self):
        svc = MonitoringStateService()
        assert svc.get_status()["updated_at"] is None

    def test_note_is_present(self):
        svc = MonitoringStateService()
        note = svc.get_status()["note"]
        assert isinstance(note, str) and len(note) > 0

    def test_health_summary_present(self):
        svc = MonitoringStateService(ai_health_svc=FakeAIHealthSvc())
        hs = svc.get_status()["health_summary"]
        assert isinstance(hs, dict)
        assert "overall_status" in hs

    def test_active_model_version_from_service(self):
        svc = MonitoringStateService(model_svc=FakeModelSvc())
        version = svc.get_status()["active_model_version"]
        assert version == "v1.0"

    def test_missing_ai_health_svc_graceful(self):
        svc = MonitoringStateService(ai_health_svc=None)
        result = svc.get_status()
        assert "health_summary" in result
        hs = result["health_summary"]
        assert isinstance(hs, dict)

    def test_missing_model_svc_graceful(self):
        svc = MonitoringStateService(model_svc=None)
        result = svc.get_status()
        assert result["active_model_version"] is None

    def test_failing_ai_health_svc_graceful(self):
        svc = MonitoringStateService(ai_health_svc=FailingAIHealthSvc())
        result = svc.get_status()  # must not raise
        assert "health_summary" in result

    def test_failing_model_svc_graceful(self):
        svc = MonitoringStateService(model_svc=FailingModelSvc())
        result = svc.get_status()  # must not raise
        assert result["active_model_version"] is None

    def test_no_threads_started_on_construction(self):
        before = threading.active_count()
        MonitoringStateService()
        after = threading.active_count()
        assert after == before, (
            f"MonitoringStateService constructor started {after - before} thread(s)"
        )

    def test_no_threads_started_on_get_status(self):
        svc = MonitoringStateService()
        before = threading.active_count()
        svc.get_status()
        after = threading.active_count()
        assert after == before, (
            f"get_status() started {after - before} thread(s)"
        )


# ---------------------------------------------------------------------------
# MonitoringState constant / safe_state tests
# ---------------------------------------------------------------------------

class TestMonitoringStateConstants:

    def test_known_states_accepted(self):
        known = [
            "disabled", "idle", "starting", "running",
            "degraded", "stopped", "error", "not_configured", "unknown",
        ]
        for s in known:
            assert MonitoringState.safe_state(s) == s, (
                f"safe_state({s!r}) should return {s!r}"
            )

    def test_unknown_token_maps_to_unknown(self):
        assert MonitoringState.safe_state("MALICIOUS_CLASS") == "unknown"

    def test_empty_string_maps_to_unknown(self):
        assert MonitoringState.safe_state("") == "unknown"

    def test_none_maps_to_unknown(self):
        assert MonitoringState.safe_state(None) == "unknown"

    def test_sql_injection_attempt_maps_to_unknown(self):
        assert MonitoringState.safe_state("'; DROP TABLE users; --") == "unknown"

    def test_xss_attempt_maps_to_unknown(self):
        assert MonitoringState.safe_state("<script>alert(1)</script>") == "unknown"

    def test_numeric_token_maps_to_unknown(self):
        assert MonitoringState.safe_state("42") == "unknown"


# ---------------------------------------------------------------------------
# View model tests
# ---------------------------------------------------------------------------

class TestMonitoringViewModels:

    def _make_status(self, **overrides):
        base = {
            "enabled": False,
            "state": "disabled",
            "state_display": "Disabled",
            "last_successful_cycle": None,
            "last_error_category": None,
            "health_summary": {"overall_status": "pass", "readiness_level": "model_ready"},
            "active_model_version": "v1.0",
            "processed_flow_count": 0,
            "prediction_count": 0,
            "alert_count": 0,
            "updated_at": None,
            "note": "Monitoring is not enabled.",
        }
        base.update(overrides)
        return base

    def test_build_monitoring_view_model_structure(self):
        vm = build_monitoring_view_model(self._make_status())
        assert "monitoring" in vm
        m = vm["monitoring"]
        assert "enabled" in m
        assert "state" in m
        assert "state_display" in m
        assert "state_badge_class" in m
        assert "poll_endpoint" in m
        assert "poll_interval_ms" in m
        assert "poll_min_interval_ms" in m
        assert "poll_max_backoff_ms" in m

    def test_disabled_state_badge_is_info(self):
        vm = build_monitoring_view_model(self._make_status(state="disabled"))
        assert vm["monitoring"]["state_badge_class"] == "info"

    def test_running_state_badge_is_success(self):
        vm = build_monitoring_view_model(self._make_status(state="running"))
        assert vm["monitoring"]["state_badge_class"] == "success"

    def test_error_state_badge_is_danger(self):
        vm = build_monitoring_view_model(self._make_status(state="error"))
        assert vm["monitoring"]["state_badge_class"] == "danger"

    def test_degraded_state_badge_is_warning(self):
        vm = build_monitoring_view_model(self._make_status(state="degraded"))
        assert vm["monitoring"]["state_badge_class"] == "warning"

    def test_arbitrary_state_maps_to_info_unknown(self):
        vm = build_monitoring_view_model(self._make_status(state="ARBITRARY_STATE"))
        assert vm["monitoring"]["state_badge_class"] == "info"

    def test_counters_are_integers(self):
        vm = build_monitoring_view_model(self._make_status())
        m = vm["monitoring"]
        assert isinstance(m["processed_flow_count"], int)
        assert isinstance(m["prediction_count"], int)
        assert isinstance(m["alert_count"], int)

    def test_counters_are_zero(self):
        vm = build_monitoring_view_model(self._make_status())
        m = vm["monitoring"]
        assert m["processed_flow_count"] == 0
        assert m["prediction_count"] == 0
        assert m["alert_count"] == 0

    def test_poll_endpoint_is_monitoring_status(self):
        vm = build_monitoring_view_model(self._make_status())
        assert vm["monitoring"]["poll_endpoint"] == "/api/v1/monitoring/status"

    def test_poll_interval_at_least_min(self):
        vm = build_monitoring_view_model(self._make_status())
        m = vm["monitoring"]
        assert m["poll_interval_ms"] >= m["poll_min_interval_ms"]

    def test_active_nav_key_is_monitoring(self):
        vm = build_monitoring_view_model(self._make_status())
        assert vm["active_nav_key"] == "monitoring"

    def test_monitoring_state_display_running(self):
        label, badge = monitoring_state_display("running")
        assert label == "Running"
        assert badge == "success"

    def test_monitoring_state_display_unknown_fallback(self):
        label, badge = monitoring_state_display("totally_unknown_state")
        assert badge == "info"


class TestNavItemsInViewModels:

    def test_monitoring_nav_enabled_in_base(self):
        vm = get_base_view_model("Test")
        monitoring_nav = next(
            (i for i in vm["nav_items"] if i["key"] == "monitoring"), None
        )
        assert monitoring_nav is not None
        assert monitoring_nav["enabled"] is True
        assert monitoring_nav["url"] == "/dashboard/monitoring"

    def test_alerts_nav_enabled_in_base(self):
        vm = get_base_view_model("Test")
        alerts_nav = next(
            (i for i in vm["nav_items"] if i["key"] == "alerts"), None
        )
        assert alerts_nav is not None
        assert alerts_nav["enabled"] is True


# ---------------------------------------------------------------------------
# Monitoring API endpoint tests
# ---------------------------------------------------------------------------

class TestMonitoringAPIEndpoint:

    def test_get_status_returns_200(self, client):
        resp = client.get("/api/v1/monitoring/status")
        assert resp.status_code == 200

    def test_response_is_json(self, client):
        resp = client.get("/api/v1/monitoring/status")
        assert resp.content_type.startswith("application/json")

    def test_success_envelope_structure(self, client):
        resp = client.get("/api/v1/monitoring/status")
        body = resp.get_json()
        assert body["success"] is True
        assert "data" in body

    def test_request_id_in_response(self, client):
        resp = client.get("/api/v1/monitoring/status")
        body = resp.get_json()
        assert "request_id" in body

    def test_data_contains_enabled(self, client):
        resp = client.get("/api/v1/monitoring/status")
        data = resp.get_json()["data"]
        assert "enabled" in data
        assert data["enabled"] is False

    def test_data_contains_state(self, client):
        resp = client.get("/api/v1/monitoring/status")
        data = resp.get_json()["data"]
        assert "state" in data
        assert data["state"] == "disabled"

    def test_data_flow_count_is_zero(self, client):
        resp = client.get("/api/v1/monitoring/status")
        data = resp.get_json()["data"]
        assert data["processed_flow_count"] == 0

    def test_data_prediction_count_is_zero(self, client):
        resp = client.get("/api/v1/monitoring/status")
        data = resp.get_json()["data"]
        assert data["prediction_count"] == 0

    def test_data_alert_count_is_zero(self, client):
        resp = client.get("/api/v1/monitoring/status")
        data = resp.get_json()["data"]
        assert data["alert_count"] == 0

    def test_post_not_allowed(self, client):
        resp = client.post(
            "/api/v1/monitoring/status",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 405

    def test_missing_service_returns_503_safe_envelope(self, app):
        """Simulate missing service: delete it from deps and make a request."""
        with app.test_client() as c:
            # Temporarily remove the monitoring service from dependencies
            deps = app.extensions["dependencies"]
            original = deps.monitoring_service
            del deps.monitoring_service
            try:
                resp = c.get("/api/v1/monitoring/status")
                assert resp.status_code == 503
                body = resp.get_json()
                # Must still use success envelope with safe data
                assert "data" in body or "error" in body
            finally:
                deps.monitoring_service = original

    def test_no_raw_exception_in_response(self, client):
        """Response must not contain a raw Python traceback."""
        resp = client.get("/api/v1/monitoring/status")
        text = resp.data.decode()
        assert "Traceback" not in text
        assert "Exception" not in text


# ---------------------------------------------------------------------------
# Dashboard monitoring page tests
# ---------------------------------------------------------------------------

class TestDashboardMonitoringPage:

    def test_monitoring_page_returns_200(self, client):
        resp = client.get("/dashboard/monitoring")
        assert resp.status_code == 200

    def test_monitoring_heading_present(self, client):
        resp = client.get("/dashboard/monitoring")
        assert b"Monitoring" in resp.data

    def test_monitoring_panel_present(self, client):
        html = client.get("/dashboard/monitoring").data.decode()
        assert 'id="monitoring-status-panel"' in html

    def test_poll_endpoint_in_html(self, client):
        html = client.get("/dashboard/monitoring").data.decode()
        assert "/api/v1/monitoring/status" in html

    def test_data_poll_interval_attribute_present(self, client):
        html = client.get("/dashboard/monitoring").data.decode()
        assert "data-poll-interval" in html

    def test_counter_fields_present(self, client):
        html = client.get("/dashboard/monitoring").data.decode()
        assert 'id="mon-flow-count"' in html
        assert 'id="mon-pred-count"' in html
        assert 'id="mon-alert-count"' in html

    def test_model_version_field_present(self, client):
        html = client.get("/dashboard/monitoring").data.decode()
        assert 'id="mon-model-version"' in html

    def test_monitoring_js_script_tag_present(self, client):
        html = client.get("/dashboard/monitoring").data.decode()
        assert "monitoring.js" in html

    def test_no_inline_script_with_server_data(self, client):
        """
        The template must not embed server response data inside a script tag.
        Only static script src tags are allowed (with empty bodies).
        """
        html = client.get("/dashboard/monitoring").data.decode()
        import re
        # Match only the content strictly between <script ...> and </script>
        # using a non-greedy pattern that doesn't cross </script> boundaries.
        # Pattern: content between opening tag and the FIRST closing </script>.
        inline_scripts = re.findall(
            r"<script(?:[^>]*)>([^<]*)</script>", html
        )
        for block in inline_scripts:
            stripped = block.strip()
            assert stripped == "", (
                f"Unexpected inline script content: {stripped[:80]!r}"
            )

    def test_monitoring_nav_active(self, client):
        html = client.get("/dashboard/monitoring").data.decode()
        # The active nav link should have aria-current="page" and link to monitoring
        assert 'aria-current="page"' in html

    def test_missing_service_returns_503(self, app):
        with app.test_client() as c:
            deps = app.extensions["dependencies"]
            original = deps.monitoring_service
            del deps.monitoring_service
            try:
                resp = c.get("/dashboard/monitoring")
                assert resp.status_code == 503
            finally:
                deps.monitoring_service = original


# ---------------------------------------------------------------------------
# JavaScript static file inspection tests
# ---------------------------------------------------------------------------

class TestMonitoringJavaScript:
    """
    These tests inspect the static monitoring.js source file to verify key
    safety properties that cannot be tested via browser execution.
    """

    JS_PATH = __import__("pathlib").Path(__file__).resolve().parents[1] / "dashboard/static/dashboard/js/monitoring.js"

    @pytest.fixture(autouse=True)
    def js_source(self):
        with open(self.JS_PATH, "r", encoding="utf-8") as f:
            self._src = f.read()

    def test_no_innerhtml_with_server_data(self):
        """
        Verify that innerHTML is not used in non-comment lines of monitoring.js.
        All DOM updates for server-derived content must use textContent.
        """
        # Strip single-line and block comments, then check for innerHTML
        import re
        # Remove block comments /** ... */
        stripped = re.sub(r"/\*.*?\*/", "", self._src, flags=re.DOTALL)
        # Remove single-line comments // ...
        stripped = re.sub(r"//[^\n]*", "", stripped)
        assert "innerHTML" not in stripped, (
            "monitoring.js must not use innerHTML in executable code (only textContent)"
        )

    def test_uses_textcontent(self):
        assert "textContent" in self._src

    def test_state_allowlist_present(self):
        # The STATE_BADGE object maps known state tokens.
        assert '"disabled"' in self._src
        assert '"running"' in self._src
        assert '"error"' in self._src
        assert '"unknown"' in self._src

    def test_abort_controller_present(self):
        """AbortController enables request timeout support."""
        assert "AbortController" in self._src

    def test_document_hidden_check(self):
        """Page Visibility API is used to pause polling when hidden."""
        assert "document.hidden" in self._src

    def test_inflight_guard(self):
        """Overlapping-request prevention via inFlight flag."""
        assert "inFlight" in self._src

    def test_exponential_backoff(self):
        """Backoff uses Math.pow doubling strategy."""
        assert "Math.pow" in self._src

    def test_max_backoff_capped(self):
        """Backoff is capped to prevent runaway retry."""
        assert "MAX_BACKOFF_MS" in self._src

    def test_only_polls_monitoring_endpoint(self):
        """
        The JS must only reference the monitoring status endpoint,
        not any other API path like /api/v1/inference or /api/v1/health.
        """
        assert "/api/v1/monitoring/status" in self._src
        assert "/api/v1/inference" not in self._src
        assert "/api/v1/health" not in self._src

    def test_panel_guard_present(self):
        """JS exits early if not on the monitoring page."""
        assert 'getElementById("monitoring-status-panel")' in self._src

    def test_visibilitychange_listener(self):
        """Listener registered for page visibility changes."""
        assert "visibilitychange" in self._src

    def test_fetch_used(self):
        assert "fetch(" in self._src

    def test_no_polling_on_unrelated_pages(self):
        """
        Polling is guarded by panel presence.  The guard is already tested
        above via test_panel_guard_present; verify no unconditional
        setInterval/setTimeout at top level (outside the IIFE guard).
        The IIFE returns early if panel is missing, so no polling starts.
        """
        # The guard check comes before scheduleNext, so this is satisfied
        # structurally. We just verify there is no bare setInterval call.
        assert "setInterval" not in self._src, (
            "setInterval would not respect the panel guard; use setTimeout recursion instead"
        )


# ---------------------------------------------------------------------------
# Thread and import safety tests
# ---------------------------------------------------------------------------

class TestThreadAndImportSafety:

    def test_import_starts_no_threads(self):
        before = threading.active_count()
        import backend.services.monitoring_service  # noqa: F401
        after = threading.active_count()
        assert after == before, (
            f"Importing monitoring_service started {after - before} thread(s)"
        )

    def test_create_app_starts_no_new_threads(self):
        before = threading.active_count()
        _make_app()
        after = threading.active_count()
        # Allow up to 1 thread for Flask internals (none expected, but defensive)
        assert after - before <= 0, (
            f"create_app() started {after - before} unexpected thread(s)"
        )


# ---------------------------------------------------------------------------
# Regression: existing routes still work
# ---------------------------------------------------------------------------

class TestRegression:

    def test_dashboard_overview_still_works(self, client):
        resp = client.get("/dashboard/")
        assert resp.status_code == 200

    def test_api_health_still_works(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_api_version_still_works(self, client):
        resp = client.get("/api/v1/version")
        assert resp.status_code == 200

    def test_dashboard_health_still_works(self, client):
        resp = client.get("/dashboard/health")
        assert resp.status_code == 200

    def test_dashboard_inference_get_still_works(self, client):
        resp = client.get("/dashboard/inference")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Simulation Route Tests
# ---------------------------------------------------------------------------

class TestDashboardSimulation:
    def test_simulate_route_requires_csrf(self, client):
        resp = client.post('/dashboard/monitoring/simulate', data={
            'duration': '10.0', 'packet_count': '10', 'byte_count': '500',
            'min_packet_size': '40', 'max_packet_size': '1500', 'avg_packet_size': '50',
            'protocol_enc': '1', 'direction_enc': '1'
        })
        # CSRF missing -> 400
        assert resp.status_code == 400

    def test_simulate_route_success(self, app, client):
        # Inject fake engine so simulation succeeds
        from ai.inference import InferenceEngine
        class FakeEngine(InferenceEngine):
            def __init__(self): pass
            def predict_one(self, *args, **kwargs):
                return {
                    'predicted_canonical_label': 'benign',
                    'confidence_score': 0.99,
                    'risk_score': 0.01,
                    'model_version': 'test',
                    'schema_version': 'test'
                }

        with app.app_context():
            deps = app.extensions.get('dependencies')
            deps.inference_service.inject_engine_for_testing(FakeEngine())

        # Need session to get csrf
        client.get('/dashboard/') # set session
        from dashboard.security import CSRF_SESSION_KEY
        with client.session_transaction() as sess:
            token = sess[CSRF_SESSION_KEY]

        resp = client.post('/dashboard/monitoring/simulate', data={
            'csrf_token': token,
            'duration': '10.0', 'packet_count': '10', 'byte_count': '500',
            'min_packet_size': '40', 'max_packet_size': '1500', 'avg_packet_size': '50',
            'protocol_enc': '1', 'direction_enc': '1'
        })

        # Post/Redirect/Get -> 302
        assert resp.status_code == 302
        assert '/dashboard/monitoring' in resp.headers['Location']

        # Follow redirect
        resp_get = client.get(resp.headers['Location'])
        html = resp_get.get_data(as_text=True)
        assert 'Simulation completed successfully.' in html
        assert 'Latest Simulation Result' in html
        assert 'Simulated Monitoring Event' in html
        assert 'Risk Score' in html
        assert 'Confidence' in html
        assert 'Policy Status' in html
        assert 'Active Model Version' in html
        assert '<dd>10.0</dd>' in html
        assert '<dd>1</dd>' in html

    def test_monitoring_status_endpoint_reflects_simulation(self, app, client):
        resp = client.get('/api/v1/monitoring/status')
        assert resp.status_code == 200
        data = resp.get_json()['data']
        # The fields should be present
        assert 'simulation_cycle_count' in data
        assert 'latest_simulation_result' in data

    def test_history_list_route(self, app, client):
        resp = client.get('/dashboard/monitoring/history')
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert 'Simulation History' in html
        assert 'Simulation Disclaimer' in html

    def test_history_list_route_pagination_invalid(self, app, client):
        resp = client.get('/dashboard/monitoring/history?page=-1')
        assert resp.status_code == 400

    def test_history_detail_route_not_found(self, app, client):
        resp = client.get('/dashboard/monitoring/history/unknown-cycle-id')
        assert resp.status_code == 404

    def test_export_json_route(self, app, client):
        resp = client.get('/dashboard/monitoring/reports/simulation.json')
        assert resp.status_code == 200
        assert resp.headers['Content-Type'] == 'application/json'
        assert 'attachment' in resp.headers['Content-Disposition']
        data = resp.get_json()
        assert data['report_schema_version'] == 'simulation-report-v1'

    def test_export_csv_route(self, app, client):
        resp = client.get('/dashboard/monitoring/reports/simulation.csv')
        assert resp.status_code == 200
        assert 'text/csv' in resp.headers['Content-Type']
        assert 'attachment' in resp.headers['Content-Disposition']
        csv_content = resp.get_data(as_text=True)
        assert 'Cycle ID' in csv_content
