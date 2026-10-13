import pytest
from sqlalchemy import create_engine, inspect, text

from database.schema import (
    create_schema,
    drop_schema,
    reset_schema,
    get_registered_tables,
    verify_schema
)
from utils.exceptions import DatabaseError

@pytest.fixture
def memory_engine():
    """Provides a fresh in-memory SQLite engine for schema testing."""
    return create_engine("sqlite:///:memory:", echo=False)

def test_get_registered_tables():
    tables = get_registered_tables()
    assert "users" in tables
    assert "devices" in tables
    assert "traffic_records" in tables
    assert "threat_logs" in tables
    assert "alerts" in tables
    assert "blocked_ips" in tables
    assert "blocked_devices" in tables
    assert "system_events" in tables
    assert "audit_logs" in tables

def test_create_and_verify_schema(memory_engine):
    # Verify should fail before creation (returns False)
    assert not verify_schema(engine=memory_engine)
    
    # Create schema
    create_schema(engine=memory_engine)
    
    # Verify should pass after creation
    assert verify_schema(engine=memory_engine)
    
    # Check that tables exist physically
    inspector = inspect(memory_engine)
    existing_tables = set(inspector.get_table_names())
    assert "users" in existing_tables

def test_drop_schema_requires_confirm(memory_engine):
    with pytest.raises(DatabaseError, match="Safety abort: confirm=True is required to drop schema."):
        drop_schema(engine=memory_engine)

def test_reset_schema_requires_confirm(memory_engine):
    with pytest.raises(DatabaseError, match="Safety abort: confirm=True is required to reset schema."):
        reset_schema(engine=memory_engine)

def test_drop_schema_with_confirm(memory_engine):
    create_schema(engine=memory_engine)
    assert verify_schema(engine=memory_engine)
    
    drop_schema(confirm=True, engine=memory_engine)
    assert not verify_schema(engine=memory_engine)

def test_reset_schema_with_confirm(memory_engine):
    create_schema(engine=memory_engine)
    # Reset it
    reset_schema(confirm=True, engine=memory_engine)
    assert verify_schema(engine=memory_engine)

def test_schema_functions_do_not_insert_data(memory_engine):
    create_schema(engine=memory_engine)
    
    # Ensure tables are empty
    with memory_engine.connect() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM users"))
        count = result.scalar()
        assert count == 0
