import datetime
from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError

from database.models import ThreatLog
from database.repositories.base_repository import BaseRepository
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

class ThreatRepository(BaseRepository[ThreatLog]):
    def __init__(self, session: Session):
        super().__init__(ThreatLog, session)

    def query_by_severity(self, severity: str, limit: int = 100, offset: int = 0) -> List[ThreatLog]:
        try:
            stmt = select(ThreatLog).where(ThreatLog.severity == severity).order_by(ThreatLog.detected_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying threats by severity: {e}")
            raise DatabaseError("Error querying threats by severity", details={"error": str(e)})

    def query_by_threat_type(self, threat_type: str, limit: int = 100, offset: int = 0) -> List[ThreatLog]:
        try:
            stmt = select(ThreatLog).where(ThreatLog.threat_type == threat_type).order_by(ThreatLog.detected_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying threats by type: {e}")
            raise DatabaseError("Error querying threats by type", details={"error": str(e)})

    def query_by_source_ip(self, ip_address: str, limit: int = 100, offset: int = 0) -> List[ThreatLog]:
        try:
            stmt = select(ThreatLog).where(ThreatLog.source_ip == ip_address).order_by(ThreatLog.detected_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying threats by source IP: {e}")
            raise DatabaseError("Error querying threats by source IP", details={"error": str(e)})

    def query_within_time_range(self, start_time: datetime.datetime, end_time: datetime.datetime, limit: int = 100, offset: int = 0) -> List[ThreatLog]:
        try:
            stmt = select(ThreatLog).where(
                ThreatLog.detected_at >= start_time,
                ThreatLog.detected_at <= end_time
            ).order_by(ThreatLog.detected_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying threats within time range: {e}")
            raise DatabaseError("Error querying threats within time range", details={"error": str(e)})

    def retrieve_recent_threats(self, limit: int = 100, offset: int = 0) -> List[ThreatLog]:
        try:
            stmt = select(ThreatLog).order_by(ThreatLog.detected_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving recent threats: {e}")
            raise DatabaseError("Error retrieving recent threats", details={"error": str(e)})

    def count_by_severity(self, severity: str) -> int:
        try:
            stmt = select(func.count()).select_from(ThreatLog).where(ThreatLog.severity == severity)
            result = self.session.execute(stmt)
            return result.scalar_one()
        except SQLAlchemyError as e:
            logger.error(f"Error counting threats by severity: {e}")
            raise DatabaseError("Error counting threats by severity", details={"error": str(e)})
