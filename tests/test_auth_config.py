from backend.app_factory import create_app


def test_authentication_and_session_security_defaults():
    app = create_app({"TESTING": True, "AUTHENTICATION_REQUIRED": True})
    assert app.config["AUTHENTICATION_REQUIRED"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 8 * 60 * 60


def test_legacy_test_compatibility_requires_testing_mode():
    assert create_app({"TESTING": True}).config["AUTHENTICATION_REQUIRED"] is False
    assert create_app().config["AUTHENTICATION_REQUIRED"] is True
