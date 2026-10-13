from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.models import SystemEvent
from database.repositories.base_repository import BaseRepository
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

class SystemEventRepository(BaseRepository[SystemEvent]):
    def __init__(self, session: Session):
        super().__init__(SystemEvent, session)

    def query_by_event_type(self, event_type: str, limit: int = 100, offset: int = 0) -> List[SystemEvent]:
        try:
            stmt = select(SystemEvent).where(SystemEvent.event_type == event_type).order_by(SystemEvent.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying system events by type: {e}")
            raise DatabaseError("Error querying system events by type", details={"error": str(e)})

    def query_by_level(self, level: str, limit: int = 100, offset: int = 0) -> List[SystemEvent]:
        try:
            stmt = select(SystemEvent).where(SystemEvent.level == level).order_by(SystemEvent.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying system events by level: {e}")
            raise DatabaseError("Error querying system events by level", details={"error": str(e)})

    def retrieve_recent_events(self, limit: int = 100, offset: int = 0) -> List[SystemEvent]:
        try:
            stmt = select(SystemEvent).order_by(SystemEvent.created_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving recent system events: {e}")
            raise DatabaseError("Error retrieving recent system events", details={"error": str(e)})
