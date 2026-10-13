from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ConfigValidation:
    ready: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


class ProductionConfigService:
    PLACEHOLDER_SECRETS = {
        "", "secret", "changeme",
        "super-secret-placeholder-key-for-development",
    }

    def validate(self, config):
        errors, warnings = [], []
        environment = str(config.get("ENVIRONMENT", "development")).lower()
        if environment not in {"development", "testing", "production"}:
            errors.append("environment_invalid")
        production = environment == "production"
        secret = str(config.get("SECRET_KEY") or "")
        if production and (
            secret.casefold() in self.PLACEHOLDER_SECRETS
            or len(secret) < 32
        ):
            errors.append("secret_key_weak")
        if production and config.get("DEBUG"):
            errors.append("debug_enabled")
        if production and config.get("DEMO_MODE"):
            errors.append("demo_mode_enabled")
        database_uri = str(config.get("DATABASE_URI") or "")
        if production and (
            not database_uri or urlsplit(database_uri).scheme not in {
                "sqlite", "postgresql", "postgresql+psycopg", "mysql",
                "mysql+pymysql",
            }
        ):
            errors.append("database_url_invalid")
        if production and not config.get("SESSION_COOKIE_SECURE"):
            errors.append("secure_cookie_disabled")
        lifetime = config.get("PERMANENT_SESSION_LIFETIME")
        seconds = lifetime.total_seconds() if hasattr(lifetime, "total_seconds") else 0
        if not 300 <= seconds <= 86_400:
            errors.append("session_lifetime_invalid")
        hosts = config.get("TRUSTED_HOSTS") or ()
        if production and (not hosts or "*" in hosts):
            errors.append("trusted_hosts_invalid")
        proxy_hops = config.get("TRUSTED_PROXY_HOPS", 0)
        if not isinstance(proxy_hops, int) or isinstance(proxy_hops, bool) or not 0 <= proxy_hops <= 4:
            errors.append("trusted_proxy_hops_invalid")
        worker_count = config.get("WEB_WORKER_COUNT", 1)
        if not isinstance(worker_count, int) or isinstance(worker_count, bool) or worker_count < 1:
            errors.append("worker_count_invalid")
        if production and config.get("ALERT_NOTIFICATION_PROVIDER") == "fake":
            errors.append("fake_notification_provider")
        if (
            production and config.get("ALERT_NOTIFICATIONS_ENABLED")
            and (
                config.get("ALERT_NOTIFICATION_PROVIDER") != "email"
                or not config.get("ALERT_NOTIFICATION_RECIPIENT")
            )
        ):
            errors.append("notification_configuration_invalid")
        if production and config.get("DEFENSIVE_ACTION_PROVIDER") == "fake":
            errors.append("fake_defensive_provider")
        if (
            production and config.get("DEFENSIVE_ACTIONS_ENABLED")
            and config.get("DEFENSIVE_ACTION_PROVIDER") == "unavailable"
        ):
            errors.append("defensive_configuration_invalid")
        if production and config.get("CAPTURE_SOURCE") == "fake":
            errors.append("demo_capture_enabled")
        if config.get("CAPTURE_ENABLED") and worker_count != 1:
            errors.append("capture_requires_single_owner")
        if config.get("LOG_DESTINATION") not in {"file", "stdout"}:
            errors.append("log_destination_missing")
        if not config.get("MIGRATION_STRICT", False):
            warnings.append("migration_check_not_strict")
        if worker_count > 1:
            warnings.append("process_local_runtime_state")
        return ConfigValidation(not errors, tuple(sorted(set(errors))),
                                tuple(sorted(set(warnings))))
