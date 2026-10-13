from datetime import datetime, timezone
import uuid

from database.models.audit_log import AuditLog
from database.session import session_scope


class SecurityAuditService:
    def record(self, action, target_category, target_id=None, outcome="success",
               actor_public_user_id=None, request_id=None, safe_error_category=None):
        with session_scope() as session:
            event = AuditLog(
                public_event_id=str(uuid.uuid4()),
                actor_public_user_id=actor_public_user_id,
                action=action, entity_type=target_category, entity_id=target_id,
                outcome=outcome, safe_error_category=safe_error_category,
                request_id=request_id, schema_version="security-audit-v1",
                occurred_at=datetime.now(timezone.utc), details=None,
            )
            session.add(event)
            session.flush()
            return event.public_event_id
