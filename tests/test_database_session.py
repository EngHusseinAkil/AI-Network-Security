import pytest
from sqlalchemy.orm import Session
from database.session import get_session, session_scope
from utils.exceptions import DatabaseError

def test_get_session(monkeypatch):
    monkeypatch.setenv("APP_ENV", "testing")
    session = get_session()
    assert isinstance(session, Session)
    session.close()

def test_session_scope_success(monkeypatch):
    monkeypatch.setenv("APP_ENV", "testing")
    with session_scope() as session:
        assert isinstance(session, Session)
    # If no exception is raised, commit and close happened automatically

def test_session_scope_rollback(monkeypatch):
    monkeypatch.setenv("APP_ENV", "testing")
    
    with pytest.raises(DatabaseError, match="Transaction failed:"):
        with session_scope() as session:
            from sqlalchemy.exc import SQLAlchemyError
            # Simulate a database failure
            raise SQLAlchemyError("Simulated DB Error")
            
def test_session_scope_unexpected_error(monkeypatch):
    monkeypatch.setenv("APP_ENV", "testing")
    
    with pytest.raises(ValueError, match="Unexpected logic error"):
        with session_scope() as session:
            # Simulate an application logic failure
            raise ValueError("Unexpected logic error")
