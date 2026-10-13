from tests.defensive_action_test_support import alert, make_service


def test_apply_and_remove_replay_call_provider_once_each():
    service, provider, _ = make_service()
    apply_token = service.generate_apply_token(alert(), "csrf")
    action, _ = service.apply("alert-1", apply_token, "csrf")
    replay, replayed = service.apply("alert-1", apply_token, "csrf")
    assert replayed and replay["action_id"] == action["action_id"]
    remove_token = service.generate_remove_token(action, "csrf")
    removed, _ = service.remove("alert-1", action["action_id"], remove_token, "csrf")
    replay_removed, replayed = service.remove(
        "alert-1", action["action_id"], remove_token, "csrf"
    )
    assert replayed and replay_removed["status"] == "removed"
    assert [call[0] for call in provider.calls] == ["apply", "remove"]


def test_failed_remove_replays_safely_but_fresh_action_can_retry():
    service, provider, _ = make_service(remove_outcome="timeout")
    apply_token = service.generate_apply_token(alert(), "csrf")
    action, _ = service.apply("alert-1", apply_token, "csrf")
    failed_token = service.generate_remove_token(action, "csrf")
    try:
        service.remove("alert-1", action["action_id"], failed_token, "csrf")
    except Exception:
        pass
    replay, replayed = service.remove(
        "alert-1", action["action_id"], failed_token, "csrf"
    )
    assert replayed and replay["status"] == "applied"
    provider.remove_outcome = "removed"
    fresh = service.generate_remove_token(replay, "csrf")
    removed, replayed = service.remove("alert-1", action["action_id"], fresh, "csrf")
    assert not replayed and removed["status"] == "removed"


def test_durable_action_survives_service_reconstruction(db_session, monkeypatch):
    from contextlib import contextmanager
    from datetime import datetime, timezone
    from backend.services.defensive_action_persistence_service import (
        DefensiveActionPersistenceService,
    )
    from database.models.alert import Alert

    db_session.add(Alert(
        public_alert_id="alert-1", alert_type="suspected_ddos", severity="high",
        status="new", title="Alert", description="Safe", source_category="test",
        confidence_score=.9, risk_score=.8, deduplication_key="z" * 64,
        occurrence_count=1, version=1, created_at=datetime.now(timezone.utc),
        safe_metadata={},
    ))
    db_session.commit()

    @contextmanager
    def scope():
        yield db_session
        db_session.commit()

    module = "backend.services.defensive_action_persistence_service"
    monkeypatch.setattr(f"{module}.get_session", lambda: db_session)
    monkeypatch.setattr(f"{module}.session_scope", scope)
    values = {
        "public_action_id": "action-1", "alert_public_id": "alert-1",
        "request_identity": "q" * 64, "action_type": "temporary_deny",
        "target_category": "demo_device", "target_reference_id": "safe-ref",
        "masked_target_label": "Target ****", "provider_category": "fake",
        "provider_reference": None, "requested_at": datetime.now(timezone.utc),
        "applied_at": None, "expires_at": None, "removed_at": None,
        "status": "pending", "safe_error_category": None,
        "reason_code": "operator_defensive_review", "duration_seconds": 900,
        "action_schema_version": "defensive-action-v1",
        "removal_request_identity": None,
    }
    DefensiveActionPersistenceService().create_pending(**values)
    rebuilt = DefensiveActionPersistenceService()
    assert rebuilt.find_by_request_identity("q" * 64)["action_id"] == "action-1"
