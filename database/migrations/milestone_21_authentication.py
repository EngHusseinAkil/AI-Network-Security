"""Reversible SQLite-compatible authentication schema extension.

SQLite table locks serialize writes during the identity backfill. Production
operators should take a backup and run this migration during a maintenance
window before deploying authentication-enabled application processes.
"""
import uuid

from sqlalchemy import inspect, text

USER_COLUMNS = (
    ("public_user_id", "VARCHAR(36)"),
    ("normalized_login", "VARCHAR(255)"),
    ("last_login_at", "DATETIME"),
    ("failed_login_count", "INTEGER NOT NULL DEFAULT 0"),
    ("locked_until", "DATETIME"),
    ("password_changed_at", "DATETIME"),
    ("version", "INTEGER NOT NULL DEFAULT 1"),
)
AUDIT_COLUMNS = (
    ("public_event_id", "VARCHAR(36)"),
    ("actor_public_user_id", "VARCHAR(36)"),
    ("outcome", "VARCHAR(32)"),
    ("safe_error_category", "VARCHAR(64)"),
    ("occurred_at", "DATETIME"),
    ("request_id", "VARCHAR(36)"),
    ("schema_version", "VARCHAR(64)"),
)


def _add_missing(connection, table, columns):
    existing = {column["name"] for column in inspect(connection).get_columns(table)}
    for name, sql_type in columns:
        if name not in existing:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))


def upgrade(engine):
    with engine.begin() as connection:
        _add_missing(connection, "users", USER_COLUMNS)
        _add_missing(connection, "audit_logs", AUDIT_COLUMNS)
        users = connection.execute(text(
            "SELECT id, username, public_user_id, normalized_login FROM users"
        )).mappings().all()
        normalized_values = []
        for user in users:
            normalized = user["normalized_login"] or user["username"].strip().casefold()
            normalized_values.append(normalized)
            connection.execute(text(
                "UPDATE users SET public_user_id = :public_id, "
                "normalized_login = :normalized WHERE id = :id"
            ), {
                "public_id": user["public_user_id"] or str(uuid.uuid4()),
                "normalized": normalized,
                "id": user["id"],
            })
        if len(normalized_values) != len(set(normalized_values)):
            raise ValueError("Existing user logins collide after normalization")
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_public_user_id "
            "ON users(public_user_id)"
        ))
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_normalized_login "
            "ON users(normalized_login)"
        ))
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_public_event_id "
            "ON audit_logs(public_event_id)"
        ))


def downgrade(engine):
    with engine.begin() as connection:
        for index in (
            "ux_audit_public_event_id", "ux_users_normalized_login",
            "ux_users_public_user_id",
        ):
            connection.execute(text(f"DROP INDEX IF EXISTS {index}"))
        for table, columns in (("audit_logs", AUDIT_COLUMNS), ("users", USER_COLUMNS)):
            existing = {column["name"] for column in inspect(connection).get_columns(table)}
            for name, _ in reversed(columns):
                if name in existing:
                    connection.execute(text(f"ALTER TABLE {table} DROP COLUMN {name}"))
