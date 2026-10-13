import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, or_
from sqlalchemy.exc import SQLAlchemyError

from database.models import BlockedIP, BlockedDevice
from utils.exceptions import DatabaseError
from utils.logger import get_logger
from utils.time_utils import get_current_utc_time

logger = get_logger(__name__)

class BlocklistRepository:
    def __init__(self, session: Session):
        self.session = session

    def find_active_ip_block(self, ip_address: str) -> Optional[BlockedIP]:
        try:
            now = get_current_utc_time()
            stmt = select(BlockedIP).where(
                BlockedIP.ip_address == ip_address,
                BlockedIP.is_active == True,
                or_(BlockedIP.expires_at == None, BlockedIP.expires_at > now)
            )
            result = self.session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            logger.error(f"Error finding active IP block: {e}")
            raise DatabaseError("Error finding active IP block", details={"error": str(e)})

    def find_active_device_block(self, mac_address: str) -> Optional[BlockedDevice]:
        try:
            now = get_current_utc_time()
            stmt = select(BlockedDevice).where(
                BlockedDevice.mac_address == mac_address,
                BlockedDevice.is_active == True,
                or_(BlockedDevice.expires_at == None, BlockedDevice.expires_at > now)
            )
            result = self.session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            logger.error(f"Error finding active device block: {e}")
            raise DatabaseError("Error finding active device block", details={"error": str(e)})

    def list_active_blocked_ips(self, limit: int = 100, offset: int = 0) -> List[BlockedIP]:
        try:
            now = get_current_utc_time()
            stmt = select(BlockedIP).where(
                BlockedIP.is_active == True,
                or_(BlockedIP.expires_at == None, BlockedIP.expires_at > now)
            ).order_by(BlockedIP.blocked_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error listing active blocked IPs: {e}")
            raise DatabaseError("Error listing active blocked IPs", details={"error": str(e)})

    def list_active_blocked_devices(self, limit: int = 100, offset: int = 0) -> List[BlockedDevice]:
        try:
            now = get_current_utc_time()
            stmt = select(BlockedDevice).where(
                BlockedDevice.is_active == True,
                or_(BlockedDevice.expires_at == None, BlockedDevice.expires_at > now)
            ).order_by(BlockedDevice.blocked_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error listing active blocked devices: {e}")
            raise DatabaseError("Error listing active blocked devices", details={"error": str(e)})

    def is_block_expired(self, block: BlockedIP | BlockedDevice) -> bool:
        if block.expires_at is None:
            return False
        return block.expires_at <= get_current_utc_time()

    def retrieve_ip_block_history(self, ip_address: str, limit: int = 100, offset: int = 0) -> List[BlockedIP]:
        try:
            stmt = select(BlockedIP).where(BlockedIP.ip_address == ip_address).order_by(BlockedIP.blocked_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving IP block history: {e}")
            raise DatabaseError("Error retrieving IP block history", details={"error": str(e)})

    def retrieve_device_block_history(self, mac_address: str, limit: int = 100, offset: int = 0) -> List[BlockedDevice]:
        try:
            stmt = select(BlockedDevice).where(BlockedDevice.mac_address == mac_address).order_by(BlockedDevice.blocked_at.desc()).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving device block history: {e}")
            raise DatabaseError("Error retrieving device block history", details={"error": str(e)})

    def add_ip_block(self, block: BlockedIP) -> BlockedIP:
        try:
            self.session.add(block)
            self.session.flush()
            return block
        except SQLAlchemyError as e:
            logger.error(f"Error adding IP block: {e}")
            raise DatabaseError("Error adding IP block", details={"error": str(e)})

    def add_device_block(self, block: BlockedDevice) -> BlockedDevice:
        try:
            self.session.add(block)
            self.session.flush()
            return block
        except SQLAlchemyError as e:
            logger.error(f"Error adding device block: {e}")
            raise DatabaseError("Error adding device block", details={"error": str(e)})
