import pytest
from database.models import AuditLog
from database.repositories.audit_repository import AuditRepository
from utils.exceptions import DatabaseError

def test_audit_repository_queries(db_session):
    repo = AuditRepository(db_session)
    
    repo.add(AuditLog(user_id=1, action="login", entity_type="system", entity_id="1"))
    repo.add(AuditLog(user_id=1, action="update", entity_type="device", entity_id="42"))
    repo.add(AuditLog(user_id=2, action="delete", entity_type="rule", entity_id="5"))
    
    user1_logs = repo.query_by_user(1)
    assert len(user1_logs) == 2
    
    update_logs = repo.query_by_action("update")
    assert len(update_logs) == 1
    assert update_logs[0].entity_type == "device"
    
    entity_logs = repo.query_by_entity("rule", "5")
    assert len(entity_logs) == 1
    assert entity_logs[0].user_id == 2
    
    recent = repo.retrieve_recent_audit_records(limit=2)
    assert len(recent) == 2

def test_audit_repository_delete_prevention(db_session):
    repo = AuditRepository(db_session)
    log = AuditLog(user_id=1, action="login", entity_type="system", entity_id="1")
    repo.add(log)
    
    with pytest.raises(DatabaseError, match="Destructive operations on audit logs are not permitted"):
        repo.delete(log)
