import pytest

from backend.services.alert_notification_service import (
    NotificationConflict, NotificationMissingAlert, NotificationUnavailable,
)
from tests.alert_notification_test_support import alert, service


def test_server_constructs_bounded_safe_message_and_sends_once():
    svc, provider, deliveries = service()
    token = svc.generate_request_token("alert-1", "csrf")
    result, replayed = svc.notify("alert-1", token, "csrf")
    assert not replayed and result["status"] == "sent"
    assert len(provider.deliveries) == 1 and len(deliveries.items) == 1


def test_missing_and_terminal_alerts_are_ineligible():
    missing, _, _ = service(alert_value={})
    with pytest.raises(NotificationMissingAlert):
        missing.notify("alert-1", missing._serializer.dumps({
            "purpose": "explicit-alert-notification-v1", "alert_id": "alert-1",
            "alert_version": 1, "schema_version": "alert-notification-v1",
            "nonce": "n", "session_digest": __import__("hashlib").sha256(b"csrf").hexdigest(),
        }), "csrf")
    terminal, _, _ = service(alert_value=alert("resolved"))
    assert terminal.generate_request_token("alert-1", "csrf") is None


def test_provider_failure_is_durably_recorded():
    svc, _, deliveries = service("timeout")
    token = svc.generate_request_token("alert-1", "csrf")
    with pytest.raises(NotificationUnavailable):
        svc.notify("alert-1", token, "csrf")
    assert next(iter(deliveries.items.values()))["status"] == "timeout"
