from unittest.mock import Mock
import pytest

from backend.app_factory import create_app


@pytest.fixture
def app():
    return create_app({"TESTING": True, "SECRET_KEY": "live-evaluation-tests"})


def token(client):
    client.get("/dashboard/monitoring")
    with client.session_transaction() as session:
        return session["_csrf_token"]


def test_evaluation_route_post_only(app):
    assert app.test_client().get("/dashboard/monitoring/flows/evaluate").status_code == 405


@pytest.mark.parametrize("submitted", [None, "invalid"])
def test_evaluation_route_requires_valid_csrf(app, submitted):
    data = {} if submitted is None else {"csrf_token": submitted}
    assert app.test_client().post(
        "/dashboard/monitoring/flows/evaluate", data=data
    ).status_code == 400


def test_cross_session_csrf_rejected(app):
    first, second = app.test_client(), app.test_client()
    assert second.post(
        "/dashboard/monitoring/flows/evaluate",
        data={"csrf_token": token(first)},
    ).status_code == 400


def test_valid_csrf_uses_303_and_fixed_flash(app):
    client = app.test_client()
    response = client.post(
        "/dashboard/monitoring/flows/evaluate",
        data={"csrf_token": token(client)},
    )
    assert response.status_code == 303 and not response.is_json
    with client.session_transaction() as session:
        assert session["_flashes"][-1][1] == (
            "Live metadata-flow evaluation completed successfully."
        )


def test_browser_overrides_are_ignored(app):
    adapter = app.extensions["dependencies"].dashboard_live_flow_evaluation_service
    adapter.evaluate = Mock()
    client = app.test_client()
    client.post("/dashboard/monitoring/flows/evaluate", data={
        "csrf_token": token(client), "batch_size": "999999",
        "features": "raw", "model": "other", "policy_threshold": "0",
    })
    adapter.evaluate.assert_called_once_with()


def test_dashboard_safe_empty_state_and_disclaimers(app):
    html = app.test_client().get("/dashboard/monitoring").get_data(as_text=True)
    assert "Live metadata-flow evaluation" in html
    assert "No live metadata-flow evaluations are retained." in html
    assert "metadata-only aggregates" in html
    assert "recommendation is not proof of an attack" in html
    assert "No alert is automatically" in html
    assert "no notification is sent" in html
    assert "no blocking occurs" in html
    assert "Create Alert" not in html


def test_status_get_does_not_evaluate(app):
    adapter = app.extensions["dependencies"].dashboard_live_flow_evaluation_service
    adapter.evaluate = Mock()
    app.test_client().get("/api/v1/monitoring/status")
    adapter.evaluate.assert_not_called()
