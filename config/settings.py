import os
from datetime import timedelta
from pathlib import Path

# Base directory of the project (two levels up from this file)
BASE_DIR = Path(__file__).resolve().parent.parent

class BaseSettings:
    """Base configuration settings applicable to all environments."""
    APP_NAME = "AI-Network-Security"
    ENVIRONMENT = "development"
    BASE_DIR = BASE_DIR

    # Core project directories
    DATA_DIR = BASE_DIR / "data"
    MODELS_DIR = BASE_DIR / "models"
    LOGS_DIR = BASE_DIR / "logs"
    TESTS_DIR = BASE_DIR / "tests"

    # Security placeholders
    # In production set SECRET_KEY via the SECRET_KEY environment variable.
    # A missing or placeholder key is detected at startup and logged as a
    # critical warning (production) or regular warning (development).
    SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-placeholder-key-for-development")

    # Session cookie security (applied by dashboard.security.configure_session_security
    # and can be overridden here per environment).
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # SESSION_COOKIE_SECURE is set dynamically in configure_session_security:
    # True in production, False in debug/test to allow plain-HTTP test clients.

    # Payload limits
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 1 * 1024 * 1024)) # Default 1MB

    # CORS Policy
    CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if os.getenv("CORS_ALLOWED_ORIGINS") else []
    CORS_ALLOW_CREDENTIALS = False

    # Rate Limiting (requests per minute)
    RATE_LIMIT_DEFAULT = int(os.getenv("RATE_LIMIT_DEFAULT", 60))
    RATE_LIMIT_INFERENCE_SINGLE = int(os.getenv("RATE_LIMIT_INFERENCE_SINGLE", 30))
    RATE_LIMIT_INFERENCE_BATCH = int(os.getenv("RATE_LIMIT_INFERENCE_BATCH", 10))
    AUTHENTICATION_REQUIRED = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    DATABASE_URI = os.getenv("DATABASE_URI", f"sqlite:///{BASE_DIR / 'data' / 'dev.db'}")
    DATABASE_POOL_SIZE = int(os.getenv("DATABASE_POOL_SIZE", "5"))
    DATABASE_MAX_OVERFLOW = int(os.getenv("DATABASE_MAX_OVERFLOW", "10"))
    LOG_DESTINATION = os.getenv("LOG_DESTINATION", "file")
    TRUSTED_HOSTS = tuple(
        item.strip() for item in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",")
        if item.strip()
    )
    TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))
    WEB_WORKER_COUNT = int(os.getenv("WEB_WORKER_COUNT", "1"))
    MIGRATION_STRICT = False
    DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
    CAPTURE_ENABLED = False
    CAPTURE_SOURCE = "scapy"
    LIVE_LOCAL_NETWORK_CIDR = os.getenv("LIVE_LOCAL_NETWORK_CIDR") or None

    ALERT_NOTIFICATIONS_ENABLED = os.getenv(
        "ALERT_NOTIFICATIONS_ENABLED", "false"
    ).lower() == "true"
    ALERT_NOTIFICATION_PROVIDER = os.getenv("ALERT_NOTIFICATION_PROVIDER", "email")
    ALERT_NOTIFICATION_RECIPIENT = os.getenv("ALERT_NOTIFICATION_RECIPIENT")
    ALERT_NOTIFICATION_RECIPIENT_LABEL = os.getenv(
        "ALERT_NOTIFICATION_RECIPIENT_LABEL", "Configured security mailbox"
    )
    ALERT_NOTIFICATION_TIMEOUT_SECONDS = float(os.getenv(
        "ALERT_NOTIFICATION_TIMEOUT_SECONDS", "10"
    ))
    ALERT_NOTIFICATION_FAKE_OUTCOME = os.getenv(
        "ALERT_NOTIFICATION_FAKE_OUTCOME", "sent"
    )

    DEFENSIVE_ACTIONS_ENABLED = False
    DEFENSIVE_ACTION_PROVIDER = "unavailable"
    DEFENSIVE_ACTION_DEFAULT_DURATION_SECONDS = 900
    DEFENSIVE_ACTION_MAXIMUM_DURATION_SECONDS = 86_400


class DevelopmentSettings(BaseSettings):
    """Configuration for development environment."""
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    DATABASE_URI = f"sqlite:///{BASE_DIR / 'data' / 'dev.db'}"

class TestingSettings(BaseSettings):
    """Configuration for testing environment."""
    DEBUG = True
    ENVIRONMENT = "testing"
    LOG_LEVEL = "DEBUG"
    # Use an in-memory database for fast, isolated tests
    DATABASE_URI = "sqlite:///:memory:"

class ProductionSettings(BaseSettings):
    """Configuration for production environment."""
    DEBUG = False
    ENVIRONMENT = "production"
    LOG_LEVEL = "INFO"
    # Production database should be configured via environment variables
    DATABASE_URI = os.getenv("DATABASE_URI", "")
    # Enforce HTTPS-only session cookie in production.
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"
    MIGRATION_STRICT = os.getenv("MIGRATION_STRICT", "true").lower() == "true"
