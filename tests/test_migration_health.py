from sqlalchemy import create_engine, text

from backend.services.migration_health_service import MigrationHealthService
from database.base import Base
import database.models


def test_current_schema_reports_expected_revision():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    result = MigrationHealthService(lambda: engine).inspect()
    assert result.status == "current"
    assert not result.migration_required


def test_legacy_and_unavailable_schema_fail_safely():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY)"))
    behind = MigrationHealthService(lambda: engine).inspect()
    assert behind.status == "behind"
    assert behind.migration_required
    unavailable = MigrationHealthService(
        lambda: (_ for _ in ()).throw(RuntimeError("credential=secret"))
    ).inspect()
    assert unavailable.status == "unavailable"
    assert unavailable.safe_error_category == "schema_inspection_failed"
