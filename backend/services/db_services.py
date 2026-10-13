"""
Read-Only Database Query Services.
"""
from typing import Dict, Any, List, Optional
import logging

from database.session import session_scope
from database.repositories.device_repository import DeviceRepository
from database.repositories.traffic_repository import TrafficRepository
from database.repositories.threat_repository import ThreatRepository
from backend.errors.exceptions import ResourceNotFoundError, InternalApiError
from backend.schemas.database import (
    serialize_device, serialize_traffic_record, serialize_threat_log, build_pagination_meta
)

logger = logging.getLogger(__name__)

class DeviceQueryService:
    def get_devices(self, page: int, page_size: int) -> Dict[str, Any]:
        """Returns paginated list of devices."""
        try:
            with session_scope() as session:
                repo = DeviceRepository(session)
                total = repo.count()
                offset = (page - 1) * page_size
                devices = repo.get_all(limit=page_size, offset=offset)

                serialized = [serialize_device(d) for d in devices]
                return {
                    "items": serialized,
                    "pagination": build_pagination_meta(page, page_size, total)
                }
        except Exception as e:
            logger.error(f"DeviceQueryService.get_devices failed: {e}")
            raise InternalApiError("Failed to query devices.") from e

    def get_device(self, device_id: int) -> Dict[str, Any]:
        """Returns a single device or raises 404."""
        try:
            with session_scope() as session:
                repo = DeviceRepository(session)
                device = repo.get_by_id(device_id)
                if not device:
                    raise ResourceNotFoundError(f"Device with ID {device_id} not found.")
                return {"item": serialize_device(device)}
        except ResourceNotFoundError:
            raise
        except Exception as e:
            logger.error(f"DeviceQueryService.get_device failed: {e}")
            raise InternalApiError("Failed to query device.") from e

class TrafficQueryService:
    def get_traffic(self, page: int, page_size: int) -> Dict[str, Any]:
        try:
            with session_scope() as session:
                repo = TrafficRepository(session)
                total = repo.count()
                offset = (page - 1) * page_size
                traffic = repo.get_all(limit=page_size, offset=offset)

                serialized = [serialize_traffic_record(t) for t in traffic]
                return {
                    "items": serialized,
                    "pagination": build_pagination_meta(page, page_size, total)
                }
        except Exception as e:
            logger.error(f"TrafficQueryService.get_traffic failed: {e}")
            raise InternalApiError("Failed to query traffic records.") from e

    def get_traffic_record(self, record_id: int) -> Dict[str, Any]:
        try:
            with session_scope() as session:
                repo = TrafficRepository(session)
                record = repo.get_by_id(record_id)
                if not record:
                    raise ResourceNotFoundError(f"Traffic record with ID {record_id} not found.")
                return {"item": serialize_traffic_record(record)}
        except ResourceNotFoundError:
            raise
        except Exception as e:
            logger.error(f"TrafficQueryService.get_traffic_record failed: {e}")
            raise InternalApiError("Failed to query traffic record.") from e

class ThreatQueryService:
    def get_threats(self, page: int, page_size: int) -> Dict[str, Any]:
        try:
            with session_scope() as session:
                repo = ThreatRepository(session)
                total = repo.count()
                offset = (page - 1) * page_size
                threats = repo.get_all(limit=page_size, offset=offset)

                serialized = [serialize_threat_log(t) for t in threats]
                return {
                    "items": serialized,
                    "pagination": build_pagination_meta(page, page_size, total)
                }
        except Exception as e:
            logger.error(f"ThreatQueryService.get_threats failed: {e}")
            raise InternalApiError("Failed to query threats.") from e

    def get_threat(self, threat_id: int) -> Dict[str, Any]:
        try:
            with session_scope() as session:
                repo = ThreatRepository(session)
                threat = repo.get_by_id(threat_id)
                if not threat:
                    raise ResourceNotFoundError(f"Threat log with ID {threat_id} not found.")
                return {"item": serialize_threat_log(threat)}
        except ResourceNotFoundError:
            raise
        except Exception as e:
            logger.error(f"ThreatQueryService.get_threat failed: {e}")
            raise InternalApiError("Failed to query threat.") from e
