from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.models import AuditLog
from database.repositories.base_repository import BaseRepository
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

class AuditRepository(BaseRepository[AuditLog]):
    def __init__(self, session: Session):
        super().__init__(AuditLog, session)

    def query_by_user(self, user_id: int, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        try:
            stmt = select(AuditLog).where(AuditLog.user_id == user_id).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying audit logs by user: {e}")
            raise DatabaseError("Error querying audit logs by user", details={"error": str(e)})

    def query_by_action(self, action: str, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        try:
            stmt = select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying audit logs by action: {e}")
            raise DatabaseError("Error querying audit logs by action", details={"error": str(e)})

    def query_by_entity(self, entity_type: str, entity_id: str, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        try:
            stmt = select(AuditLog).where(
                AuditLog.entity_type == entity_type,
                AuditLog.entity_id == entity_id
            ).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying audit logs by entity: {e}")
            raise DatabaseError("Error querying audit logs by entity", details={"error": str(e)})

    def retrieve_recent_audit_records(self, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        try:
            stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving recent audit records: {e}")
            raise DatabaseError("Error retrieving recent audit records", details={"error": str(e)})

    def delete(self, obj: AuditLog) -> None:
        """Override delete to prevent destruction of audit records."""
        raise DatabaseError("Destructive operations on audit logs are not permitted.")
