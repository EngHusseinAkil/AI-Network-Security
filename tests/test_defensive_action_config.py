import pytest
from defense.config import DefensiveActionConfig


def test_disabled_default_and_duration_defaults():
    config = DefensiveActionConfig()
    assert not config.enabled
    assert config.default_duration_seconds == 900
    assert config.maximum_duration_seconds == 86_400


@pytest.mark.parametrize("provider", ["firewall", "powershell", ""])
def test_provider_allowlist(provider):
    with pytest.raises(ValueError):
        DefensiveActionConfig(provider=provider)


def test_fake_gating_and_duration_bounds():
    with pytest.raises(ValueError):
        DefensiveActionConfig(provider="fake")
    with pytest.raises(ValueError):
        DefensiveActionConfig(default_duration_seconds=True)
    with pytest.raises(ValueError):
        DefensiveActionConfig(maximum_duration_seconds=86_401)
