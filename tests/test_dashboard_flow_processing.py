from unittest.mock import Mock
import pytest

from backend.app_factory import create_app


@pytest.fixture
def app():
    return create_app({"TESTING": True, "SECRET_KEY": "flow-tests"})


def token(client):
    client.get("/dashboard/monitoring")
    with client.session_transaction() as session:
        return session["_csrf_token"]


def test_processing_action_is_post_only(app):
    assert app.test_client().get("/dashboard/monitoring/flows/process").status_code == 405


def test_processing_action_requires_csrf(app):
    assert app.test_client().post("/dashboard/monitoring/flows/process").status_code == 400


def test_processing_action_uses_303_prg(app):
    client = app.test_client()
    response = client.post(
        "/dashboard/monitoring/flows/process", data={"csrf_token": token(client)}
    )
    assert response.status_code == 303 and not response.is_json


def test_browser_cannot_select_batch_size(app):
    service = app.extensions["dependencies"].dashboard_flow_processing_service
    service._processor._capture.drain_metadata = Mock(return_value=())
    client = app.test_client()
    client.post("/dashboard/monitoring/flows/process",
                data={"csrf_token": token(client), "batch_size": "999999"})
    service._processor._capture.drain_metadata.assert_called_once_with(
        app.extensions["dependencies"].flow_config.max_processing_batch
    )


def test_status_get_does_not_process_or_drain(app):
    service = app.extensions["dependencies"].dashboard_flow_processing_service
    service.process = Mock()
    capture = app.extensions["dependencies"].capture_service
    capture.drain_metadata = Mock()
    app.test_client().get("/api/v1/monitoring/status")
    service.process.assert_not_called()
    capture.drain_metadata.assert_not_called()


def test_safe_empty_dashboard_state_and_disclaimers(app):
    html = app.test_client().get("/dashboard/monitoring").get_data(as_text=True)
    assert "Captured metadata processing" in html
    assert "No completed metadata flows are retained." in html
    assert "does not confirm an attack" in html
    assert "No raw payload is retained" in html
    assert "no alert is automatically created" in html
