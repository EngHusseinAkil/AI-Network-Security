"""Immutable DTOs for privacy-preserving protocol-window aggregates.

These are not TCP/IP five-tuple flows. Capture metadata contains no endpoint
identity or ports, so records represent interface/protocol/direction windows.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import math
from typing import Optional

from .constants import SUPPORTED_PROTOCOLS
from .capture_models import FlowEndpointMetadata

METADATA_FLOW_SCHEMA_VERSION = "metadata-flow-v1"


class FlowCompletionReason(str, Enum):
    WINDOW_CLOSED = "window_closed"
    INACTIVITY_TIMEOUT = "inactivity_timeout"
    PACKET_LIMIT_REACHED = "packet_limit_reached"
    DURATION_LIMIT_REACHED = "duration_limit_reached"
    ACTIVE_FLOW_CAPACITY = "active_flow_capacity"
    CAPTURE_SESSION_STOPPED = "capture_session_stopped"
    MANUAL_FLUSH = "manual_flush"
    SOURCE_EXHAUSTED = "source_exhausted"
    UNKNOWN = "unknown"


def _utc(value, name):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _integer(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _finite(value, name):
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(value) or value < 0):
        raise ValueError(f"{name} must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class MetadataFlowKey:
    interface_key: str
    protocol: str
    direction: str
    window_bucket: int
    monitored_device_ip: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.interface_key, str) or not self.interface_key:
            raise ValueError("interface_key must be a non-empty opaque key")
        protocol = str(self.protocol).upper()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError("protocol must be normalized")
        object.__setattr__(self, "protocol", protocol)
        if self.direction not in ("inbound", "outbound", "internal", "unknown"):
            raise ValueError("direction must be normalized")
        _integer(self.window_bucket, "window_bucket")
        if self.monitored_device_ip is not None:
            if (not isinstance(self.monitored_device_ip, str)
                    or not self.monitored_device_ip.strip()):
                raise ValueError("monitored_device_ip must be a non-empty string or None")


@dataclass(frozen=True, slots=True)
class MetadataFlowRecord:
    flow_id: str
    interface_key: str
    protocol: str
    direction: str
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    packet_count: int
    total_bytes: int
    minimum_packet_length: int
    maximum_packet_length: int
    mean_packet_length: float
    completed_reason: FlowCompletionReason
    source_mode: str
    capture_session_id: Optional[str]
    schema_version: str = METADATA_FLOW_SCHEMA_VERSION
    endpoint_metadata: Optional[FlowEndpointMetadata] = None
    monitored_device_ip: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.flow_id, str) or not self.flow_id:
            raise ValueError("flow_id must be non-empty")
        if not isinstance(self.interface_key, str) or not self.interface_key:
            raise ValueError("interface_key must be non-empty")
        protocol = str(self.protocol).upper()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError("protocol must be normalized")
        object.__setattr__(self, "protocol", protocol)
        if self.direction not in ("inbound", "outbound", "internal", "unknown"):
            raise ValueError("direction must be normalized")
        object.__setattr__(self, "first_seen", _utc(self.first_seen, "first_seen"))
        object.__setattr__(self, "last_seen", _utc(self.last_seen, "last_seen"))
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        _finite(self.duration_seconds, "duration_seconds")
        for name in ("packet_count", "total_bytes", "minimum_packet_length", "maximum_packet_length"):
            _integer(getattr(self, name), name)
        _finite(self.mean_packet_length, "mean_packet_length")
        if self.minimum_packet_length > self.maximum_packet_length:
            raise ValueError("minimum packet length exceeds maximum")
        if not isinstance(self.completed_reason, FlowCompletionReason):
            raise ValueError("completed_reason must be FlowCompletionReason")
        if self.source_mode not in ("scapy", "fake"):
            raise ValueError("source_mode must be safe")
        if self.schema_version != METADATA_FLOW_SCHEMA_VERSION:
            raise ValueError("unsupported metadata flow schema")
        if self.endpoint_metadata is not None and not isinstance(self.endpoint_metadata, FlowEndpointMetadata):
            raise ValueError("endpoint_metadata must be FlowEndpointMetadata or None")
        if self.monitored_device_ip is not None:
            if (not isinstance(self.monitored_device_ip, str)
                    or not self.monitored_device_ip.strip()):
                raise ValueError("monitored_device_ip must be a non-empty string or None")


@dataclass(frozen=True, slots=True)
class FlowAggregationSnapshot:
    active_flow_count: int
    completed_flow_count: int
    completed_flow_eviction_count: int
    latest_completed_flow: Optional[MetadataFlowRecord]

    def __post_init__(self):
        _integer(self.active_flow_count, "active_flow_count")
        _integer(self.completed_flow_count, "completed_flow_count")
        _integer(self.completed_flow_eviction_count, "completed_flow_eviction_count")


@dataclass(frozen=True, slots=True)
class NetworkFeatureVector:
    duration: float
    packet_count: int
    byte_count: int
    min_packet_size: int
    max_packet_size: int
    avg_packet_size: float
    protocol_enc: int
    direction_enc: int

    def __post_init__(self):
        for name in ("duration", "avg_packet_size"):
            _finite(getattr(self, name), name)
        for name in ("packet_count", "byte_count", "min_packet_size",
                     "max_packet_size", "protocol_enc", "direction_enc"):
            _integer(getattr(self, name), name)

    def as_ordered_tuple(self):
        return (
            self.duration, self.packet_count, self.byte_count,
            self.min_packet_size, self.max_packet_size, self.avg_packet_size,
            self.protocol_enc, self.direction_enc,
        )


@dataclass(frozen=True, slots=True)
class FeatureExtractionResult:
    compatible: bool
    vector: Optional[NetworkFeatureVector]
    incompatibility_reason: Optional[str]
