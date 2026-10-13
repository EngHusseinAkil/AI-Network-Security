import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.models import Device
from database.repositories.base_repository import BaseRepository
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

class DeviceRepository(BaseRepository[Device]):
    def __init__(self, session: Session):
        super().__init__(Device, session)

    def get_by_mac_address(self, mac_address: str) -> Optional[Device]:
        try:
            stmt = select(Device).where(Device.mac_address == mac_address)
            result = self.session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching device by mac: {e}")
            raise DatabaseError("Error fetching device by mac", details={"error": str(e)})

    def get_by_ip_address(self, ip_address: str) -> Optional[Device]:
        try:
            stmt = select(Device).where(Device.ip_address == ip_address)
            result = self.session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching device by ip: {e}")
            raise DatabaseError("Error fetching device by ip", details={"error": str(e)})

    def list_high_risk_devices(self, risk_threshold: float, limit: int = 100, offset: int = 0) -> List[Device]:
        try:
            stmt = select(Device).where(Device.risk_score >= risk_threshold).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error listing high risk devices: {e}")
            raise DatabaseError("Error listing high risk devices", details={"error": str(e)})

    def list_recently_seen_devices(self, since: datetime.datetime, limit: int = 100, offset: int = 0) -> List[Device]:
        try:
            stmt = select(Device).where(Device.last_seen >= since).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error listing recently seen devices: {e}")
            raise DatabaseError("Error listing recently seen devices", details={"error": str(e)})
