import pytest
from sqlalchemy import Engine
from database.connection import get_engine, test_connection as db_test_connection
from database import connection

def test_get_engine(monkeypatch):
    # Ensure it uses an isolated memory db for test
    monkeypatch.setattr("config.settings.DATABASE_URI", "sqlite:///:memory:")
    
    # Reset singleton for testing
    connection._engine = None
    
    engine = get_engine()
    assert isinstance(engine, Engine)
    assert str(engine.url) == "sqlite:///:memory:"
    
    # Test singleton
    engine2 = get_engine()
    assert engine is engine2

def test_database_connection(monkeypatch):
    monkeypatch.setattr("config.settings.DATABASE_URI", "sqlite:///:memory:")
    connection._engine = None
    assert db_test_connection() is True
