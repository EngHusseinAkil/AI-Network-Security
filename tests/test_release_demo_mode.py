from datetime import timedelta

from backend.app_factory import create_app
from backend.services.production_config_service import ProductionConfigService


def test_production_rejects_demo_mode():
    config = {
        "ENVIRONMENT": "production",
        "SECRET_KEY": "x" * 48,
        "DEBUG": False,
        "DATABASE_URI": "postgresql://db/security",
        "SESSION_COOKIE_SECURE": True,
        "PERMANENT_SESSION_LIFETIME": timedelta(hours=8),
        "TRUSTED_HOSTS": ("security.example",),
        "TRUSTED_PROXY_HOPS": 1,
        "WEB_WORKER_COUNT": 1,
        "LOG_DESTINATION": "stdout",
        "MIGRATION_STRICT": True,
        "DEMO_MODE": True,
    }
    result = ProductionConfigService().validate(config)
    assert not result.ready
    assert "demo_mode_enabled" in result.errors


def test_demo_seed_requires_explicit_demo_mode():
    app = create_app({
        "TESTING": True,
        "ENVIRONMENT": "testing",
        "DEMO_MODE": False,
    })
    result = app.test_cli_runner().invoke(args=["demo", "seed"], input="y\n")
    assert result.exit_code != 0
    assert "Set DEMO_MODE=true" in result.output


def test_login_is_visibly_labeled_in_demo_mode():
    app = create_app({
        "TESTING": True,
        "AUTHENTICATION_REQUIRED": True,
        "DEMO_MODE": True,
    })
    response = app.test_client().get("/login")
    assert response.status_code == 200
    assert b"DEMO MODE - synthetic data and fake providers only" in response.data
