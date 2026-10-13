import datetime
from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError

from database.models import TrafficRecord
from database.repositories.base_repository import BaseRepository
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

class TrafficRepository(BaseRepository[TrafficRecord]):
    def __init__(self, session: Session):
        super().__init__(TrafficRecord, session)

    def query_by_source_ip(self, ip_address: str, limit: int = 100, offset: int = 0) -> List[TrafficRecord]:
        try:
            stmt = select(TrafficRecord).where(TrafficRecord.source_ip == ip_address).order_by(TrafficRecord.captured_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying traffic by source IP: {e}")
            raise DatabaseError("Error querying traffic by source IP", details={"error": str(e)})

    def query_by_destination_ip(self, ip_address: str, limit: int = 100, offset: int = 0) -> List[TrafficRecord]:
        try:
            stmt = select(TrafficRecord).where(TrafficRecord.destination_ip == ip_address).order_by(TrafficRecord.captured_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying traffic by destination IP: {e}")
            raise DatabaseError("Error querying traffic by destination IP", details={"error": str(e)})

    def query_by_protocol(self, protocol: str, limit: int = 100, offset: int = 0) -> List[TrafficRecord]:
        try:
            stmt = select(TrafficRecord).where(TrafficRecord.protocol == protocol).order_by(TrafficRecord.captured_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying traffic by protocol: {e}")
            raise DatabaseError("Error querying traffic by protocol", details={"error": str(e)})

    def query_within_time_range(self, start_time: datetime.datetime, end_time: datetime.datetime, limit: int = 100, offset: int = 0) -> List[TrafficRecord]:
        try:
            stmt = select(TrafficRecord).where(
                TrafficRecord.captured_at >= start_time,
                TrafficRecord.captured_at <= end_time
            ).order_by(TrafficRecord.captured_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error querying traffic within time range: {e}")
            raise DatabaseError("Error querying traffic within time range", details={"error": str(e)})

    def retrieve_recent_traffic(self, limit: int = 100, offset: int = 0) -> List[TrafficRecord]:
        try:
            stmt = select(TrafficRecord).order_by(TrafficRecord.captured_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving recent traffic: {e}")
            raise DatabaseError("Error retrieving recent traffic", details={"error": str(e)})

    def count_within_time_range(self, start_time: datetime.datetime, end_time: datetime.datetime) -> int:
        try:
            stmt = select(func.count()).select_from(TrafficRecord).where(
                TrafficRecord.captured_at >= start_time,
                TrafficRecord.captured_at <= end_time
            )
            result = self.session.execute(stmt)
            return result.scalar_one()
        except SQLAlchemyError as e:
            logger.error(f"Error counting traffic within time range: {e}")
            raise DatabaseError("Error counting traffic within time range", details={"error": str(e)})
