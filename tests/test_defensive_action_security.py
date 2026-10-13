import threading

from backend.app_factory import create_app


def test_startup_and_status_are_inert_and_no_worker_created():
    before = {thread.ident for thread in threading.enumerate()}
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    deps = app.extensions["dependencies"]
    assert deps.defensive_action_provider.status() == "unavailable"
    assert app.test_client().get("/api/v1/monitoring/status").status_code == 200
    assert deps.dashboard_defensive_action_service.status()["active_temporary_action_count"] == 0
    assert {thread.ident for thread in threading.enumerate()} == before


def test_live_metadata_alert_without_mapping_has_safe_reason():
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    service = app.extensions["dependencies"].defensive_action_service
    recommendation = service.recommendation({
        "public_alert_id": "live-alert", "status": "new", "severity": "critical",
        "source_category": "live_metadata_flow",
    })
    assert not recommendation.eligible
    assert recommendation.ineligibility_reason == "defensive_actions_disabled"
