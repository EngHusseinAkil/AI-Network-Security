from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import pytest

from defense.models import DefensiveActionRecommendation


def test_recommendation_is_immutable_and_utc():
    value = DefensiveActionRecommendation(
        "r", "a", "temporary_deny", "demo", "masked", 900, "reason",
        datetime.now(timezone.utc), "defensive-action-v1", True,
    )
    with pytest.raises(FrozenInstanceError):
        value.eligible = False


def test_recommendation_has_no_native_or_command_fields():
    fields = DefensiveActionRecommendation.__dataclass_fields__
    assert not {"native_value", "ip", "mac", "command", "credentials"} & set(fields)
