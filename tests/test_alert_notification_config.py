import pytest
from notifications.config import AlertNotificationConfig


def test_disabled_default():
    assert AlertNotificationConfig().enabled is False


@pytest.mark.parametrize("provider", ["webhook", "smtp", ""])
def test_provider_allowlist(provider):
    with pytest.raises(ValueError):
        AlertNotificationConfig(provider=provider)


def test_fake_provider_gated_and_control_characters_rejected():
    with pytest.raises(ValueError):
        AlertNotificationConfig(provider="fake")
    with pytest.raises(ValueError):
        AlertNotificationConfig(recipient="bad\r\n@example.test")


@pytest.mark.parametrize("timeout", [True, 0, 61])
def test_timeout_bounds(timeout):
    with pytest.raises(ValueError):
        AlertNotificationConfig(provider_timeout_seconds=timeout)
