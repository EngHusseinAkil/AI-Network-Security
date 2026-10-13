import pytest
from sqlalchemy import text
from database.connection import get_engine
from database.schema import create_schema, drop_schema
from database.integrity import (
    check_database_connectivity,
    check_required_tables,
    check_schema_integrity,
    get_database_status_report
)

def test_database_connectivity():
    assert check_database_connectivity() is True

def test_check_required_tables_missing():
    engine = get_engine()
    # Drop all to ensure empty state
    drop_schema(confirm=True, engine=engine)
    
    status = check_required_tables()
    assert status["status"] == "warning"
    assert "Database reachable but schema not initialized" in status["message"]

def test_check_required_tables_complete():
    engine = get_engine()
    create_schema(engine=engine)
    
    status = check_required_tables()
    assert status["status"] == "success"
    assert status["message"] == "All required tables are present"

def test_check_schema_integrity():
    engine = get_engine()
    create_schema(engine=engine)
    assert check_schema_integrity() is True

def test_get_database_status_report():
    engine = get_engine()
    create_schema(engine=engine)
    report = get_database_status_report()
    assert report["connectivity"] == "success"
    assert report["tables_status"]["status"] == "success"
    assert report["schema_integrity"] == "success"

def test_foreign_key_enforcement_sqlite():
    engine = get_engine()
    if engine.url.drivername == "sqlite":
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA foreign_keys")).scalar()
            assert result == 1
