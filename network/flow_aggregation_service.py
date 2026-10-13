"""Thread-safe bounded aggregation of approved capture metadata only."""
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import math
import threading
import time
import uuid

from .capture_models import CapturedPacketMetadata
from .flow_config import MetadataFlowConfig
from .flow_models import (
    FlowAggregationSnapshot, FlowCompletionReason, MetadataFlowKey,
    MetadataFlowRecord,
)


def _monitored_device_ip(metadata: CapturedPacketMetadata):
    """Return the local hotspot endpoint used to segment live aggregates."""
    endpoint = metadata.endpoint_metadata
    if endpoint is None:
        return None
    if metadata.direction == "inbound":
        return endpoint.destination_ip
    # Outbound, internal, and unknown traffic retain a deterministic source
    # association.  The value is metadata only and never enters features.
    return endpoint.source_ip


@dataclass(slots=True)
class _ActiveFlow:
    key: MetadataFlowKey
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    total_bytes: int
    minimum: int
    maximum: int
    last_update_mono: float
    sequence: int
    source_mode: str
    session_id: str | None
    endpoint_metadata: object | None


class FlowAggregationService:
    def __init__(self, config: MetadataFlowConfig, monotonic_clock=None, utc_clock=None):
        self._config = config
        self._monotonic = monotonic_clock or time.monotonic
        self._utc = utc_clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._active = {}
        self._completed = deque()
        self._completed_evictions = 0
        self._sequence = 0

    def accept(self, metadata: CapturedPacketMetadata, *, source_mode, capture_session_id=None):
        if not isinstance(metadata, CapturedPacketMetadata):
            raise ValueError("only CapturedPacketMetadata is accepted")
        if source_mode not in ("scapy", "fake"):
            raise ValueError("invalid source mode")
        now_mono = self._monotonic()
        bucket = math.floor(metadata.timestamp.timestamp() / self._config.aggregation_window_seconds)
        monitored_device_ip = _monitored_device_ip(metadata)
        key = MetadataFlowKey(
            metadata.interface_key, metadata.protocol, metadata.direction or "unknown", bucket,
            monitored_device_ip,
        )
        finalized = []
        with self._lock:
            finalized.extend(self._expire_locked(now_mono))
            identity = (key.interface_key, key.protocol, key.direction, key.monitored_device_ip)
            for old_key in tuple(self._active):
                if ((old_key.interface_key, old_key.protocol, old_key.direction,
                     old_key.monitored_device_ip) == identity
                        and old_key.window_bucket < key.window_bucket):
                    finalized.append(self._finalize_locked(old_key, FlowCompletionReason.WINDOW_CLOSED))
            active = self._active.get(key)
            if active is not None:
                proposed_duration = max(
                    active.last_seen, metadata.timestamp
                ).timestamp() - min(active.first_seen, metadata.timestamp).timestamp()
                if proposed_duration > self._config.max_flow_duration_seconds:
                    finalized.append(self._finalize_locked(key, FlowCompletionReason.DURATION_LIMIT_REACHED))
                    active = None
            if active is None:
                if len(self._active) >= self._config.max_active_flows:
                    victim = min(self._active.values(), key=lambda item: (item.last_update_mono, item.sequence))
                    finalized.append(self._finalize_locked(victim.key, FlowCompletionReason.ACTIVE_FLOW_CAPACITY))
                self._sequence += 1
                active = _ActiveFlow(
                    key, metadata.timestamp, metadata.timestamp, 0, 0,
                    metadata.packet_length, metadata.packet_length, now_mono,
                    self._sequence, source_mode, capture_session_id,
                    metadata.endpoint_metadata,
                )
                self._active[key] = active
            active.first_seen = min(active.first_seen, metadata.timestamp)
            active.last_seen = max(active.last_seen, metadata.timestamp)
            active.packet_count += 1
            active.total_bytes += metadata.packet_length
            active.minimum = min(active.minimum, metadata.packet_length)
            active.maximum = max(active.maximum, metadata.packet_length)
            active.last_update_mono = now_mono
            if active.packet_count >= self._config.max_packets_per_flow:
                finalized.append(self._finalize_locked(key, FlowCompletionReason.PACKET_LIMIT_REACHED))
        return tuple(finalized)

    def expire_inactive(self):
        with self._lock:
            return tuple(self._expire_locked(self._monotonic()))

    def flush(self, reason=FlowCompletionReason.MANUAL_FLUSH, capture_session_id=None):
        if not isinstance(reason, FlowCompletionReason):
            raise ValueError("invalid completion reason")
        with self._lock:
            keys = [
                key for key, active in self._active.items()
                if capture_session_id is None or active.session_id == capture_session_id
            ]
            return tuple(self._finalize_locked(key, reason) for key in keys)

    def completed_snapshot(self, limit=None):
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
            raise ValueError("limit must be a positive integer")
        with self._lock:
            values = tuple(self._completed)
            return values if limit is None else values[-limit:]

    def status_snapshot(self):
        with self._lock:
            return FlowAggregationSnapshot(
                len(self._active), len(self._completed), self._completed_evictions,
                self._completed[-1] if self._completed else None,
            )

    def _expire_locked(self, now):
        keys = [
            key for key, active in self._active.items()
            if now - active.last_update_mono >= self._config.inactivity_timeout_seconds
        ]
        return [
            self._finalize_locked(key, FlowCompletionReason.INACTIVITY_TIMEOUT)
            for key in sorted(keys, key=lambda item: self._active[item].sequence)
        ]

    def _finalize_locked(self, key, reason):
        active = self._active.pop(key)
        duration = max(0.0, (active.last_seen - active.first_seen).total_seconds())
        record = MetadataFlowRecord(
            str(uuid.uuid4()), key.interface_key, key.protocol, key.direction,
            active.first_seen, active.last_seen, duration, active.packet_count,
            active.total_bytes, active.minimum, active.maximum,
            active.total_bytes / active.packet_count, reason, active.source_mode,
            active.session_id,
            endpoint_metadata=active.endpoint_metadata,
            monitored_device_ip=key.monitored_device_ip,
        )
        if len(self._completed) >= self._config.max_completed_flows:
            self._completed.popleft()
            self._completed_evictions += 1
        self._completed.append(record)
        return record
