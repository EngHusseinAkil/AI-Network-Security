from dataclasses import dataclass

from sqlalchemy import inspect


EXPECTED_REVISION = "milestone_21_authentication"


@dataclass(frozen=True, slots=True)
class MigrationHealth:
    status: str
    current_revision: str | None
    expected_revision: str
    migration_required: bool
    safe_error_category: str | None = None


class MigrationHealthService:
    def __init__(self, engine_provider):
        self._engine_provider = engine_provider

    def inspect(self):
        try:
            inspector = inspect(self._engine_provider())
            tables = set(inspector.get_table_names())
            if "users" not in tables or "audit_logs" not in tables:
                return MigrationHealth(
                    "behind", None, EXPECTED_REVISION, True, "schema_missing"
                )
            user_columns = {
                item["name"] for item in inspector.get_columns("users")
            }
            audit_columns = {
                item["name"] for item in inspector.get_columns("audit_logs")
            }
            ready = (
                {"public_user_id", "normalized_login", "locked_until", "version"}
                <= user_columns
                and {"public_event_id", "actor_public_user_id", "request_id"}
                <= audit_columns
                and "defensive_actions" in tables
                and "notification_deliveries" in tables
            )
            return MigrationHealth(
                "current" if ready else "behind",
                EXPECTED_REVISION if ready else "legacy",
                EXPECTED_REVISION, not ready,
                None if ready else "schema_behind",
            )
        except Exception:
            return MigrationHealth(
                "unavailable", None, EXPECTED_REVISION, True,
                "schema_inspection_failed",
            )
