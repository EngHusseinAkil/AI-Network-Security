from datetime import timedelta

import pytest

from backend.app_factory import create_app
from backend.services.production_config_service import ProductionConfigService


def _production(**changes):
    config = {
        "ENVIRONMENT": "production",
        "SECRET_KEY": "x" * 48,
        "DEBUG": False,
        "DATABASE_URI": "postgresql://db/security",
        "SESSION_COOKIE_SECURE": True,
        "PERMANENT_SESSION_LIFETIME": timedelta(hours=8),
        "TRUSTED_HOSTS": ("security.example",),
        "TRUSTED_PROXY_HOPS": 1,
        "WEB_WORKER_COUNT": 2,
        "ALERT_NOTIFICATION_PROVIDER": "email",
        "DEFENSIVE_ACTION_PROVIDER": "unavailable",
        "CAPTURE_ENABLED": False,
        "CAPTURE_SOURCE": "scapy",
        "LOG_DESTINATION": "stdout",
        "MIGRATION_STRICT": True,
    }
    config.update(changes)
    return config


@pytest.mark.parametrize(("change", "error"), [
    ({"SECRET_KEY": "changeme"}, "secret_key_weak"),
    ({"DEBUG": True}, "debug_enabled"),
    ({"DEMO_MODE": True}, "demo_mode_enabled"),
    ({"DATABASE_URI": ""}, "database_url_invalid"),
    ({"SESSION_COOKIE_SECURE": False}, "secure_cookie_disabled"),
    ({"TRUSTED_HOSTS": ("*",)}, "trusted_hosts_invalid"),
    ({"ALERT_NOTIFICATION_PROVIDER": "fake"}, "fake_notification_provider"),
    ({"DEFENSIVE_ACTION_PROVIDER": "fake"}, "fake_defensive_provider"),
    ({"ALERT_NOTIFICATIONS_ENABLED": True}, "notification_configuration_invalid"),
    ({"DEFENSIVE_ACTIONS_ENABLED": True}, "defensive_configuration_invalid"),
    ({"CAPTURE_SOURCE": "fake"}, "demo_capture_enabled"),
    ({"CAPTURE_ENABLED": True}, "capture_requires_single_owner"),
])
def test_production_validation_fails_closed(change, error):
    result = ProductionConfigService().validate(_production(**change))
    assert not result.ready
    assert error in result.errors


def test_safe_production_configuration_passes():
    assert ProductionConfigService().validate(_production()).ready


def test_application_rejects_placeholder_production_secret_before_dependencies():
    with pytest.raises(RuntimeError, match="secret_key_weak"):
        create_app({"ENVIRONMENT": "production", "SECRET_KEY": "changeme"})
