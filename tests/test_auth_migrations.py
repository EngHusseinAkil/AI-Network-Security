from sqlalchemy import create_engine, inspect, text

from database.migrations.milestone_21_authentication import downgrade, upgrade


def test_auth_migration_upgrades_legacy_rows_and_downgrades():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(50) NOT NULL, "
            "email VARCHAR(255) NOT NULL, role VARCHAR(50) NOT NULL, "
            "password_hash VARCHAR(255) NOT NULL, is_active BOOLEAN NOT NULL, "
            "is_deleted BOOLEAN NOT NULL)"
        ))
        connection.execute(text(
            "CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, action VARCHAR(100) NOT NULL, "
            "entity_type VARCHAR(100) NOT NULL)"
        ))
        connection.execute(text(
            "INSERT INTO users VALUES (1, 'Alice', 'alice@example.test', 'viewer', "
            "'legacy', 1, 0)"
        ))
    upgrade(engine)
    with engine.connect() as connection:
        row = connection.execute(text(
            "SELECT public_user_id, normalized_login FROM users"
        )).one()
        assert row.public_user_id
        assert row.normalized_login == "alice"
        assert connection.execute(text(
            "SELECT actor_public_user_id FROM audit_logs"
        )).fetchall() == []
    downgrade(engine)
    assert "normalized_login" not in {
        column["name"] for column in inspect(engine).get_columns("users")
    }
