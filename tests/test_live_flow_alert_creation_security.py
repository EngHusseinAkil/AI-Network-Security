import json

from backend.app_factory import create_app
from tests.live_flow_alert_test_support import eligible_record


def test_status_contains_no_recommendation_token_and_does_not_mutate():
    app = create_app({"TESTING": True, "SECRET_KEY": "status-tests"})
    deps = app.extensions["dependencies"]
    deps.live_flow_evaluation_state_service.retain(eligible_record())
    before = deps.live_flow_evaluation_state_service.snapshot()
    response = app.test_client().get("/api/v1/monitoring/status")
    after = deps.live_flow_evaluation_state_service.snapshot()
    assert "recommendation_token" not in json.dumps(response.get_json())
    assert before == after


def test_dashboard_only_renders_create_action_for_eligible_record():
    app = create_app({"TESTING": True, "SECRET_KEY": "dashboard-tests"})
    state = app.extensions["dependencies"].live_flow_evaluation_state_service
    state.retain(eligible_record())
    html = app.test_client().get("/dashboard/monitoring").get_data(as_text=True)
    assert "Create alert" in html
    assert "no notification is sent" in html
    assert "no blocking occurs" in html
    assert "private-key-evaluation-1" not in html
