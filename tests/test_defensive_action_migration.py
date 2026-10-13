from sqlalchemy import create_engine, inspect

from database.base import Base
from database.models.alert import Alert
from database.migrations.milestone_20_defensive_actions import downgrade, upgrade


def test_migration_is_reversible_and_preserves_existing_alert_table():
    engine = create_engine("sqlite:///:memory:")
    Alert.__table__.create(engine)
    upgrade(engine)
    assert {"alerts", "defensive_actions"} <= set(inspect(engine).get_table_names())
    downgrade(engine)
    assert inspect(engine).get_table_names() == ["alerts"]
