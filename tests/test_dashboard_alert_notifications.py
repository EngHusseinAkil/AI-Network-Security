from unittest.mock import Mock

from backend.app_factory import create_app


def csrf(client):
    client.get("/dashboard/monitoring")
    with client.session_transaction() as session:
        return session["_csrf_token"]


def test_route_post_only_csrf_and_browser_fields():
    app = create_app({"TESTING": True, "SECRET_KEY": "route-secret"})
    client = app.test_client()
    path = "/dashboard/alerts/alert-1/notifications"
    assert client.get(path).status_code == 405
    assert client.post(path, data={}).status_code == 400
    assert client.post(path, data={
        "csrf_token": csrf(client), "notification_request_token": "token",
        "recipient": "attacker@example.test",
    }).status_code == 400


def test_success_is_303_prg():
    app = create_app({"TESTING": True, "SECRET_KEY": "route-secret"})
    adapter = app.extensions["dependencies"].dashboard_alert_notification_service
    adapter.notify = Mock(return_value=({"delivery_id": "delivery-1"}, False))
    client = app.test_client()
    response = client.post("/dashboard/alerts/alert-1/notifications", data={
        "csrf_token": csrf(client), "notification_request_token": "token",
    })
    assert response.status_code == 303
    assert response.headers["Location"].endswith("/dashboard/alerts/alert-1")
