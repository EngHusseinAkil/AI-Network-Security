"""
Pagination validation and Serialization schemas.
"""
from typing import Dict, Any, Optional
from flask import request
from backend.errors.exceptions import RequestValidationError
from database.models.device import Device
from database.models.traffic_record import TrafficRecord
from database.models.threat_log import ThreatLog

def parse_pagination_params(max_page_size: int = 100) -> Dict[str, int]:
    """
    Parses 'page' and 'page_size' from query parameters.
    """
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        raise RequestValidationError("Invalid page parameter. Must be an integer.")

    try:
        page_size = int(request.args.get("page_size", 20))
    except ValueError:
        raise RequestValidationError("Invalid page_size parameter. Must be an integer.")

    if page < 1:
        raise RequestValidationError("Page parameter must be >= 1.")

    if page_size < 1:
        raise RequestValidationError("Page size parameter must be >= 1.")

    if page_size > max_page_size:
        raise RequestValidationError(f"Page size parameter must not exceed {max_page_size}.")

    return {"page": page, "page_size": page_size}

def build_pagination_meta(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Builds standard pagination metadata."""
    import math
    total_pages = max(1, math.ceil(total_items / page_size)) if total_items > 0 else 0
    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_previous": page > 1 and total_items > 0
    }

def serialize_device(device: Device) -> Dict[str, Any]:
    """Safely serializes a Device entity."""
    return {
        "id": device.id,
        "mac_address": device.mac_address, # Redaction could happen here if policy requires, but we assume raw is okay for internal api
        "ip_address": device.ip_address,
        "hostname": device.hostname,
        "is_active": device.is_active,
        "risk_score": device.risk_score,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "created_at": device.created_at.isoformat() if device.created_at else None
    }

def serialize_traffic_record(record: TrafficRecord) -> Dict[str, Any]:
    """Safely serializes a TrafficRecord entity. Does NOT expose raw payload/pcap bytes."""
    return {
        "id": record.id,
        "source_ip": record.source_ip,
        "destination_ip": record.destination_ip,
        "protocol": record.protocol,
        "byte_count": record.byte_count,
        "packet_count": record.packet_count,
        "flow_duration": record.flow_duration,
        "captured_at": record.captured_at.isoformat() if record.captured_at else None
    }

def serialize_threat_log(threat: ThreatLog) -> Dict[str, Any]:
    """Safely serializes a ThreatLog entity."""
    return {
        "id": threat.id,
        "source_ip": threat.source_ip,
        "destination_ip": threat.destination_ip,
        "threat_type": threat.threat_type,
        "severity": threat.severity,
        "confidence": threat.confidence,
        "action_taken": threat.action_taken,
        "detected_at": threat.detected_at.isoformat() if threat.detected_at else None
    }
