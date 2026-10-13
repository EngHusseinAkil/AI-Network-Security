"""Immutable, privacy-preserving capture DTOs."""
from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Optional

from .constants import CaptureState, SUPPORTED_PROTOCOLS


def _utc(value, field):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _count(value, field):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")


def _duration(value, field, positive=False):
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(value) or value < 0 or (positive and value <= 0)):
        raise ValueError(f"{field} must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class FlowEndpointMetadata:
    """Payload-free endpoint identity retained for live-flow presentation joins."""
    source_ip: str
    destination_ip: str
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None

    def __post_init__(self):
        for name in ("source_ip", "destination_ip"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("source_mac", "destination_mac"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a non-empty string or None")


@dataclass(frozen=True, slots=True)
class CapturedPacketMetadata:
    timestamp: datetime
    packet_length: int
    protocol: str
    interface_key: str
    direction: Optional[str] = None
    endpoint_metadata: Optional[FlowEndpointMetadata] = None

    def __post_init__(self):
        object.__setattr__(self, "timestamp", _utc(self.timestamp, "timestamp"))
        _count(self.packet_length, "packet_length")
        protocol = str(self.protocol).upper()
        object.__setattr__(self, "protocol", protocol if protocol in SUPPORTED_PROTOCOLS else "OTHER")
        if not isinstance(self.interface_key, str) or not self.interface_key:
            raise ValueError("interface_key must be non-empty")
        if self.direction not in (None, "inbound", "outbound", "internal", "unknown"):
            raise ValueError("invalid direction")
        if self.endpoint_metadata is not None and not isinstance(self.endpoint_metadata, FlowEndpointMetadata):
            raise ValueError("endpoint_metadata must be FlowEndpointMetadata or None")


@dataclass(frozen=True, slots=True)
class CaptureStatusSnapshot:
    enabled: bool
    source: str
    state: CaptureState
    session_id: Optional[str]
    interface_key: Optional[str]
    packet_count: int
    dropped_metadata_count: int
    start_timestamp: Optional[datetime]
    elapsed_duration: float
    stop_reason: Optional[str]
    error_category: Optional[str]

    def __post_init__(self):
        if not isinstance(self.enabled, bool) or self.source not in ("scapy", "fake"):
            raise ValueError("invalid status configuration")
        if not isinstance(self.state, CaptureState):
            raise ValueError("state must be CaptureState")
        _count(self.packet_count, "packet_count")
        _count(self.dropped_metadata_count, "dropped_metadata_count")
        _duration(self.elapsed_duration, "elapsed_duration")
        if self.start_timestamp is not None:
            object.__setattr__(self, "start_timestamp", _utc(self.start_timestamp, "start_timestamp"))


@dataclass(frozen=True, slots=True)
class CaptureLimitsSnapshot:
    max_packets: Optional[int]
    max_duration_seconds: Optional[float]
    queue_size: int
    read_timeout_seconds: float
    stop_join_timeout_seconds: float

    def __post_init__(self):
        if self.max_packets is not None:
            _count(self.max_packets, "max_packets")
            if self.max_packets == 0:
                raise ValueError("max_packets must be positive")
        if self.max_duration_seconds is not None:
            _duration(self.max_duration_seconds, "max_duration_seconds", True)
        _count(self.queue_size, "queue_size")
        if self.queue_size == 0:
            raise ValueError("queue_size must be positive")
        _duration(self.read_timeout_seconds, "read_timeout_seconds", True)
        _duration(self.stop_join_timeout_seconds, "stop_join_timeout_seconds", True)


@dataclass(frozen=True, slots=True)
class CaptureSessionSummary:
    session_id: str
    interface_key: str
    start_timestamp: datetime
    stop_timestamp: datetime
    final_state: CaptureState
    packet_count: int
    dropped_metadata_count: int
    stop_reason: Optional[str]
    error_category: Optional[str]
    duration_seconds: float
    limits: CaptureLimitsSnapshot

    def __post_init__(self):
        object.__setattr__(self, "start_timestamp", _utc(self.start_timestamp, "start_timestamp"))
        object.__setattr__(self, "stop_timestamp", _utc(self.stop_timestamp, "stop_timestamp"))
        _count(self.packet_count, "packet_count")
        _count(self.dropped_metadata_count, "dropped_metadata_count")
        _duration(self.duration_seconds, "duration_seconds")
