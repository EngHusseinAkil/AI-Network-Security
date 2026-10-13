from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.models import Alert
from database.repositories.base_repository import BaseRepository
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

class AlertRepository(BaseRepository[Alert]):
    def __init__(self, session: Session):
        super().__init__(Alert, session)

    def get_by_public_id(self, public_id: str) -> Optional[Alert]:
        try:
            stmt = select(Alert).where(Alert.public_alert_id == public_id)
            result = self.session.execute(stmt)
            return result.scalars().first()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching alert by public id: {e}")
            raise DatabaseError("Error fetching alert by public id", details={"error": str(e)})

    def get_by_deduplication_key(self, key: str) -> Optional[Alert]:
        try:
            stmt = select(Alert).where(Alert.deduplication_key == key)
            result = self.session.execute(stmt)
            return result.scalars().first()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching alert by dedup key: {e}")
            raise DatabaseError("Error fetching alert by dedup key", details={"error": str(e)})

    def get_alerts(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None
    ) -> List[Alert]:
        try:
            stmt = select(Alert)
            if status:
                stmt = stmt.where(Alert.status == status)
            if severity:
                stmt = stmt.where(Alert.severity == severity)
            if alert_type:
                stmt = stmt.where(Alert.alert_type == alert_type)

            stmt = stmt.order_by(Alert.created_at.desc())
            stmt = stmt.limit(page_size).offset((page - 1) * page_size)

            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error fetching alerts: {e}")
            raise DatabaseError("Error fetching alerts", details={"error": str(e)})

    def count_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None
    ) -> int:
        from sqlalchemy import func
        try:
            stmt = select(func.count(Alert.id))
            if status:
                stmt = stmt.where(Alert.status == status)
            if severity:
                stmt = stmt.where(Alert.severity == severity)
            if alert_type:
                stmt = stmt.where(Alert.alert_type == alert_type)

            result = self.session.execute(stmt)
            return result.scalar() or 0
        except SQLAlchemyError as e:
            logger.error(f"Error counting alerts: {e}")
            raise DatabaseError("Error counting alerts", details={"error": str(e)})

    def query_by_status(self, status: str, limit: int = 100, offset: int = 0) -> List[Alert]:
        try:
            stmt = select(Alert).where(Alert.status == status).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying alerts by status: {e}")
            raise DatabaseError("Error querying alerts by status", details={"error": str(e)})

    def query_by_severity(self, severity: str, limit: int = 100, offset: int = 0) -> List[Alert]:
        try:
            stmt = select(Alert).where(Alert.severity == severity).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying alerts by severity: {e}")
            raise DatabaseError("Error querying alerts by severity", details={"error": str(e)})

    def retrieve_unresolved_alerts(self, limit: int = 100, offset: int = 0) -> List[Alert]:
        try:
            stmt = select(Alert).where(Alert.status.in_(["new", "open", "investigating"])).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving unresolved alerts: {e}")
            raise DatabaseError("Error retrieving unresolved alerts", details={"error": str(e)})

    def retrieve_recent_alerts(self, limit: int = 100, offset: int = 0) -> List[Alert]:
        try:
            stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving recent alerts: {e}")
            raise DatabaseError("Error retrieving recent alerts", details={"error": str(e)})
