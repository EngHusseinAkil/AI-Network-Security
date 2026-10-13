import sqlite3


CRITICAL_TABLES = (
    "users",
    "alerts",
    "notification_deliveries",
    "defensive_actions",
    "security_audit_events",
)


def test_sqlite_backup_restore_preserves_revision_and_critical_counts(tmp_path):
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "restored.db"

    with sqlite3.connect(source_path) as source:
        source.execute("CREATE TABLE alembic_version (version_num TEXT PRIMARY KEY)")
        source.execute(
            "INSERT INTO alembic_version VALUES ('milestone_21_authentication')"
        )
        for table in CRITICAL_TABLES:
            source.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, label TEXT)")
            source.execute(f"INSERT INTO {table} (label) VALUES (?)", (table,))
        source.commit()
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)

    with sqlite3.connect(backup_path) as restored:
        assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        revision = restored.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        assert revision == "milestone_21_authentication"
        for table in CRITICAL_TABLES:
            assert restored.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 1
