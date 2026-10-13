import pytest
from database.models import SystemEvent
from database.repositories.system_event_repository import SystemEventRepository

def test_system_event_repository_queries(db_session):
    repo = SystemEventRepository(db_session)
    
    repo.add(SystemEvent(event_type="startup", level="info", message="System started", source="core"))
    repo.add(SystemEvent(event_type="error", level="error", message="Failed to bind port", source="network"))
    
    startup = repo.query_by_event_type("startup")
    assert len(startup) == 1
    assert startup[0].message == "System started"
    
    errors = repo.query_by_level("error")
    assert len(errors) == 1
    assert errors[0].source == "network"
    
    recent = repo.retrieve_recent_events(limit=10)
    assert len(recent) == 2
