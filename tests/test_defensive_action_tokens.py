import pytest

from backend.services.defensive_action_service import (
    DefensiveActionDisabled, DefensiveActionError,
)
from tests.defensive_action_test_support import alert, make_service


def test_valid_token_and_session_binding():
    service, _, _ = make_service()
    token = service.generate_apply_token(alert(), "csrf")
    service.apply("alert-1", token, "csrf")
    with pytest.raises(DefensiveActionDisabled):
        service.apply("alert-1", token, "other")


@pytest.mark.parametrize("token", ["bad", "bad.token.value"])
def test_malformed_or_tampered_token_rejected(token):
    service, _, _ = make_service()
    with pytest.raises(DefensiveActionError):
        service.apply("alert-1", token, "csrf")


def test_notification_purpose_rejected():
    service, _, _ = make_service()
    token = service._serializer.dumps({
        "purpose": "explicit-alert-notification-v1", "alert_id": "alert-1",
        "schema_version": "defensive-action-v1",
    })
    with pytest.raises(DefensiveActionError):
        service.apply("alert-1", token, "csrf")
