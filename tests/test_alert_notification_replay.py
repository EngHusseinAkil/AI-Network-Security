from tests.alert_notification_test_support import service


def test_same_explicit_request_replays_but_fresh_request_may_send_again():
    svc, provider, _ = service()
    token = svc.generate_request_token("alert-1", "csrf")
    first, _ = svc.notify("alert-1", token, "csrf")
    replay, replayed = svc.notify("alert-1", token, "csrf")
    assert replayed and replay["delivery_id"] == first["delivery_id"]
    fresh = svc.generate_request_token("alert-1", "csrf")
    svc.notify("alert-1", fresh, "csrf")
    assert len(provider.deliveries) == 2


def test_delivery_history_survives_service_reconstruction(db_session, monkeypatch):
    from contextlib import contextmanager
    from datetime import datetime, timezone
    from backend.services.notification_delivery_service import NotificationDeliveryService
    from database.models.alert import Alert

    db_session.add(Alert(
        public_alert_id="alert-1", alert_type="suspected_ddos", severity="high",
        status="new", title="Alert", description="Safe", source_category="test",
        confidence_score=.9, risk_score=.8, deduplication_key="d" * 64,
        occurrence_count=1, version=1, created_at=datetime.now(timezone.utc),
        safe_metadata={},
    ))
    db_session.commit()

    @contextmanager
    def scope():
        yield db_session
        db_session.commit()

    module = "backend.services.notification_delivery_service"
    monkeypatch.setattr(f"{module}.get_session", lambda: db_session)
    monkeypatch.setattr(f"{module}.session_scope", scope)
    first = NotificationDeliveryService()
    first.create_pending(
        public_delivery_id="delivery-1", alert_public_id="alert-1",
        request_identity="r" * 64, provider_category="fake",
        masked_recipient_label="masked", requested_at=datetime.now(timezone.utc),
        completed_at=None, status="pending", safe_error_category=None,
        attempt_number=1, notification_schema_version="alert-notification-v1",
        provider_message_reference=None,
    )
    second = NotificationDeliveryService()
    assert second.find_by_request_identity("r" * 64)["delivery_id"] == "delivery-1"
