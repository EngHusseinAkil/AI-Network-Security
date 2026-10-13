import pytest

from backend.services.defensive_action_service import DefensiveProviderUnavailable
from tests.defensive_action_test_support import alert, make_service


def test_pending_precedes_provider_and_safe_fields_persisted():
    service, provider, actions = make_service()
    original = provider.apply_temporary_deny
    provider.apply_temporary_deny = lambda target, duration: (
        actions.events.append("provider") or original(target, duration)
    )
    token = service.generate_apply_token(alert(), "csrf")
    result, replayed = service.apply("alert-1", token, "csrf")
    assert not replayed and result["status"] == "applied"
    assert actions.events == ["pending", "provider"]
    assert "native" not in str(result)


def test_failure_is_finalized_safely():
    service, _, actions = make_service("timeout")
    token = service.generate_apply_token(alert(), "csrf")
    with pytest.raises(DefensiveProviderUnavailable):
        service.apply("alert-1", token, "csrf")
    assert next(iter(actions.items.values()))["status"] == "timeout"


def test_terminal_low_severity_and_missing_target_ineligible():
    service, _, _ = make_service(item=alert(status="resolved"))
    assert not service.recommendation(alert(status="resolved")).eligible
    assert not service.recommendation(alert(severity="low")).eligible
    empty, _, _ = make_service(mappings={})
    assert empty.recommendation(alert()).ineligibility_reason == "no_trusted_actionable_target"
