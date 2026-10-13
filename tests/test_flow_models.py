from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import math
import pytest

from network.flow_models import (
    FlowCompletionReason, MetadataFlowKey, MetadataFlowRecord,
    NetworkFeatureVector,
)


def record(**changes):
    now = datetime.now(timezone.utc)
    values = dict(
        flow_id="flow", interface_key="opaque", protocol="TCP", direction="unknown",
        first_seen=now, last_seen=now, duration_seconds=0, packet_count=1,
        total_bytes=10, minimum_packet_length=10, maximum_packet_length=10,
        mean_packet_length=10, completed_reason=FlowCompletionReason.MANUAL_FLUSH,
        source_mode="fake", capture_session_id="session",
    )
    values.update(changes)
    return MetadataFlowRecord(**values)


def test_flow_key_is_immutable_protocol_window_identity():
    key = MetadataFlowKey("opaque", "tcp", "unknown", 12)
    assert key.protocol == "TCP"
    with pytest.raises(FrozenInstanceError):
        key.window_bucket = 13


def test_record_is_immutable_and_utc_normalized():
    offset = timezone(timedelta(hours=2))
    flow = record(first_seen=datetime.now(offset), last_seen=datetime.now(offset))
    assert flow.first_seen.tzinfo is timezone.utc
    with pytest.raises(FrozenInstanceError):
        flow.packet_count = 2


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        record(first_seen=datetime.now())


@pytest.mark.parametrize(("field", "value"), [
    ("duration_seconds", math.nan), ("mean_packet_length", math.inf),
    ("packet_count", True), ("total_bytes", -1),
])
def test_invalid_flow_numbers(field, value):
    with pytest.raises(ValueError):
        record(**{field: value})


def test_record_has_no_sensitive_fields():
    names = {field.name for field in fields(MetadataFlowRecord)}
    assert names.isdisjoint({
        "source_ip", "destination_ip", "source_port", "destination_port",
        "mac_address", "payload", "packet", "headers", "native_interface",
    })


def test_feature_vector_exact_order():
    vector = NetworkFeatureVector(1, 2, 3, 1, 2, 1.5, 1, 0)
    assert vector.as_ordered_tuple() == (1, 2, 3, 1, 2, 1.5, 1, 0)
