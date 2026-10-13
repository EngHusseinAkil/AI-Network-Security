import pytest
from backend.app_factory import create_app


@pytest.fixture
def app():
    return create_app({
        "TESTING": True, "SECRET_KEY": "capture-tests", "CAPTURE_ENABLED": True,
        "CAPTURE_SOURCE": "fake",
    })


def token(client):
    client.get("/dashboard/monitoring")
    with client.session_transaction() as session:
        return session["_csrf_token"]


@pytest.mark.parametrize("path", [
    "/dashboard/monitoring/capture/interfaces/refresh",
    "/dashboard/monitoring/capture/start",
    "/dashboard/monitoring/capture/stop",
])
def test_capture_writes_are_post_only(app, path):
    assert app.test_client().get(path).status_code == 405


def test_refresh_requires_csrf(app):
    assert app.test_client().post(
        "/dashboard/monitoring/capture/interfaces/refresh"
    ).status_code == 400


def test_stop_requires_csrf(app):
    assert app.test_client().post(
        "/dashboard/monitoring/capture/stop"
    ).status_code == 400


def test_refresh_uses_prg_and_fixed_flash(app):
    client = app.test_client()
    response = client.post("/dashboard/monitoring/capture/interfaces/refresh",
                           data={"csrf_token": token(client)})
    assert response.status_code == 303 and not response.is_json
    with client.session_transaction() as session:
        assert session["_flashes"][-1][1] == "Network interfaces refreshed successfully."
        assert "native" not in repr(dict(session))


def test_invalid_interface_is_400(app):
    client = app.test_client()
    response = client.post("/dashboard/monitoring/capture/start",
                           data={"csrf_token": token(client), "interface_key": "bad"})
    assert response.status_code == 400


def test_refresh_start_stop_success(app):
    client = app.test_client()
    csrf = token(client)
    client.post("/dashboard/monitoring/capture/interfaces/refresh", data={"csrf_token": csrf})
    key = app.extensions["dependencies"].dashboard_capture_service.interfaces()[0].key
    assert client.post("/dashboard/monitoring/capture/start",
                       data={"csrf_token": csrf, "interface_key": key}).status_code == 303
    assert client.post("/dashboard/monitoring/capture/stop",
                       data={"csrf_token": csrf}).status_code == 303


def test_already_stopped_stop_is_friendly_idempotent_redirect(app):
    client = app.test_client()
    csrf = token(client)

    response = client.post("/dashboard/monitoring/capture/stop",
                           data={"csrf_token": csrf})

    assert response.status_code == 303
    assert "/dashboard/monitoring" in response.headers["Location"]
    with client.session_transaction() as session:
        assert session["_flashes"][-1] == ("info", "Capture is already stopped.")


def test_capture_controls_reflect_current_state(app):
    client = app.test_client()
    csrf = token(client)
    client.post("/dashboard/monitoring/capture/interfaces/refresh",
                data={"csrf_token": csrf})

    stopped_html = client.get("/dashboard/monitoring").get_data(as_text=True)
    assert "Start capture" in stopped_html
    assert "Stop capture" not in stopped_html

    key = app.extensions["dependencies"].dashboard_capture_service.interfaces()[0].key
    client.post("/dashboard/monitoring/capture/start",
                data={"csrf_token": csrf, "interface_key": key})
    running_html = client.get("/dashboard/monitoring").get_data(as_text=True)
    assert "Stop capture" in running_html
    assert "Start capture" not in running_html

    client.post("/dashboard/monitoring/capture/stop",
                data={"csrf_token": csrf})


def test_get_does_not_refresh(app):
    service = app.extensions["dependencies"].dashboard_capture_service
    assert service.interfaces() == ()
    app.test_client().get("/dashboard/monitoring")
    assert service.interfaces() == ()
