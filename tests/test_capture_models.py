from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import math
import pytest

from network.capture_models import (
    CapturedPacketMetadata, CaptureLimitsSnapshot, CaptureStatusSnapshot,
)
from network.constants import CaptureState


def packet(**changes):
    values = dict(timestamp=datetime.now(timezone.utc), packet_length=1,
                  protocol="tcp", interface_key="safe")
    values.update(changes)
    return CapturedPacketMetadata(**values)


def test_packet_is_frozen_and_normalized():
    item = packet()
    assert item.protocol == "TCP"
    with pytest.raises(FrozenInstanceError):
        item.protocol = "UDP"


def test_non_utc_aware_timestamp_normalized():
    value = datetime.now(timezone(timedelta(hours=2)))
    assert packet(timestamp=value).timestamp.tzinfo is timezone.utc


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        packet(timestamp=datetime.now())


@pytest.mark.parametrize("value", [-1, True, 1.2])
def test_invalid_packet_lengths(value):
    with pytest.raises(ValueError):
        packet(packet_length=value)


def test_packet_dto_has_only_safe_fields():
    assert {f.name for f in fields(CapturedPacketMetadata)} == {
        "timestamp", "packet_length", "protocol", "interface_key", "direction"
    }


@pytest.mark.parametrize("value", [math.nan, math.inf, -1, True])
def test_invalid_elapsed_duration(value):
    with pytest.raises(ValueError):
        CaptureStatusSnapshot(True, "scapy", CaptureState.RUNNING, None, None,
                              0, 0, None, value, None, None)


def test_limits_are_frozen():
    limits = CaptureLimitsSnapshot(None, None, 1, 1.0, 1.0)
    with pytest.raises(FrozenInstanceError):
        limits.queue_size = 2
