from unittest.mock import Mock

from backend.app_factory import create_app


def csrf(client):
    client.get("/dashboard/monitoring")
    with client.session_transaction() as session:
        return session["_csrf_token"]


def test_apply_and_remove_are_post_only_and_reject_browser_values():
    app = create_app({"TESTING": True, "SECRET_KEY": "route"})
    client = app.test_client()
    apply_path = "/dashboard/alerts/alert-1/defensive-actions"
    remove_path = apply_path + "/action-1/remove"
    assert client.get(apply_path).status_code == 405
    assert client.get(remove_path).status_code == 405
    assert client.post(apply_path, data={
        "csrf_token": csrf(client), "defensive_confirmation_token": "token",
        "ip": "127.0.0.1",
    }).status_code == 400


def test_apply_success_uses_303_prg():
    app = create_app({"TESTING": True, "SECRET_KEY": "route"})
    adapter = app.extensions["dependencies"].dashboard_defensive_action_service
    adapter.apply = Mock(return_value=({"action_id": "action-1"}, False))
    client = app.test_client()
    response = client.post("/dashboard/alerts/alert-1/defensive-actions", data={
        "csrf_token": csrf(client), "defensive_confirmation_token": "token",
    })
    assert response.status_code == 303
