import threading
from backend.app_factory import create_app


def test_startup_and_status_do_not_send_or_create_attempts():
    before = {thread.ident for thread in threading.enumerate()}
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    deps = app.extensions["dependencies"]
    assert deps.notification_provider.health_status() == "unavailable"
    response = app.test_client().get("/api/v1/monitoring/status")
    assert response.status_code == 200
    assert deps.dashboard_alert_notification_service.status()["notification_attempt_count"] == 0
    assert {thread.ident for thread in threading.enumerate()} == before
