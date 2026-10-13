import pytest

from backend.app_factory import create_app
from config.settings import BaseSettings, ProductionSettings
from network.capture_config import CaptureConfig


def _capture_config(app):
    return app.extensions["dependencies"].capture_service._config


def test_default_application_keeps_capture_disabled():
    app = create_app({"TESTING": True})

    config = _capture_config(app)
    assert config.enabled is False
    assert config.source == "scapy"


def test_factory_override_enables_the_actual_scapy_capture_service():
    app = create_app({
        "TESTING": True,
        "CAPTURE_ENABLED": True,
        "CAPTURE_SOURCE": "scapy",
        "WEB_WORKER_COUNT": 1,
    })

    config = _capture_config(app)
    assert config.enabled is True
    assert config.source == "scapy"
    assert app.extensions["dependencies"].dashboard_capture_service.status()["enabled"] is True


def test_factory_override_does_not_change_capture_defaults():
    overridden = create_app({
        "TESTING": True,
        "CAPTURE_ENABLED": True,
        "CAPTURE_SOURCE": "scapy",
    })
    default = create_app({"TESTING": True})

    assert _capture_config(overridden).enabled is True
    assert _capture_config(default).enabled is False
    assert BaseSettings.CAPTURE_ENABLED is False
    assert ProductionSettings.CAPTURE_ENABLED is False


def test_fake_capture_remains_gated_without_demo_permission():
    with pytest.raises(ValueError, match="fake source is not permitted"):
        CaptureConfig(
            enabled=True,
            source="fake",
            fake_source_permitted=False,
        )

    with pytest.raises(ValueError, match="fake source is not permitted"):
        create_app({
            "TESTING": False,
            "ENVIRONMENT": "development",
            "CAPTURE_ENABLED": True,
            "CAPTURE_SOURCE": "fake",
            "CAPTURE_DEMO_ENABLED": False,
        })


def test_monitoring_page_renders_status_from_current_app_service(monkeypatch):
    app = create_app({
        "TESTING": True,
        "CAPTURE_ENABLED": True,
        "CAPTURE_SOURCE": "scapy",
        "WEB_WORKER_COUNT": 1,
    })
    capture = app.extensions["dependencies"].dashboard_capture_service
    calls = []
    original_status = capture.status

    def status_from_current_service():
        calls.append(id(capture))
        return original_status()

    monkeypatch.setattr(capture, "status", status_from_current_service)
    response = app.test_client().get("/dashboard/monitoring")

    assert response.status_code == 200
    assert b"<dt>Enabled</dt><dd>Yes</dd>" in response.data
    assert calls == [id(capture)]


def test_monitoring_page_default_app_renders_capture_disabled():
    app = create_app({"TESTING": True})

    response = app.test_client().get("/dashboard/monitoring")

    assert response.status_code == 200
    assert b"<dt>Enabled</dt><dd>No</dd>" in response.data


def test_refresh_interfaces_uses_current_app_capture_service(monkeypatch):
    app = create_app({
        "TESTING": True,
        "CAPTURE_ENABLED": True,
        "CAPTURE_SOURCE": "scapy",
    })
    capture = app.extensions["dependencies"].dashboard_capture_service
    calls = []

    def refresh_from_current_service():
        calls.append(id(capture))

    monkeypatch.setattr(capture, "refresh_interfaces", refresh_from_current_service)
    client = app.test_client()
    client.get("/dashboard/monitoring")  # establishes the session CSRF token
    with client.session_transaction() as session:
        csrf_token = session["_csrf_token"]

    response = client.post(
        "/dashboard/monitoring/capture/interfaces/refresh",
        data={"csrf_token": csrf_token},
    )

    assert response.status_code == 303
    assert calls == [id(capture)]
