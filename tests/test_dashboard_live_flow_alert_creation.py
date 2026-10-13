from unittest.mock import Mock
import pytest

from backend.app_factory import create_app


@pytest.fixture
def app():
    return create_app({"TESTING": True, "SECRET_KEY": "route-tests"})


def csrf(client):
    client.get("/dashboard/monitoring")
    with client.session_transaction() as session:
        return session["_csrf_token"]


def test_route_is_post_only_and_requires_token(app):
    client = app.test_client()
    path = "/dashboard/monitoring/flows/evaluations/evaluation-1/alerts"
    assert client.get(path).status_code == 405
    assert client.post(path, data={"csrf_token": csrf(client)}).status_code == 400


def test_valid_post_uses_303_to_alert_detail(app):
    adapter = app.extensions["dependencies"].dashboard_live_flow_evaluation_service
    adapter.create_alert = Mock(return_value=("alert-1", False))
    client = app.test_client()
    response = client.post(
        "/dashboard/monitoring/flows/evaluations/evaluation-1/alerts",
        data={"csrf_token": csrf(client), "recommendation_token": "signed"},
    )
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/dashboard/alerts/alert-1")


def test_browser_alert_fields_are_rejected(app):
    client = app.test_client()
    response = client.post(
        "/dashboard/monitoring/flows/evaluations/evaluation-1/alerts",
        data={
            "csrf_token": csrf(client), "recommendation_token": "signed",
            "severity": "critical",
        },
    )
    assert response.status_code == 400
