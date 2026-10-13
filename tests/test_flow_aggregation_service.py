from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

from network.capture_models import CapturedPacketMetadata
from network.flow_aggregation_service import FlowAggregationService
from network.flow_config import MetadataFlowConfig
from network.flow_models import FlowCompletionReason

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def packet(seconds=0, length=10, protocol="TCP", direction=None, interface="key"):
    return CapturedPacketMetadata(
        BASE + timedelta(seconds=seconds), length, protocol, interface, direction
    )


def service(**config):
    mono = [0.0]
    result = FlowAggregationService(
        MetadataFlowConfig(**config), monotonic_clock=lambda: mono[0],
        utc_clock=lambda: BASE,
    )
    return result, mono


def test_first_metadata_creates_active_flow():
    flows, _ = service()
    assert flows.accept(packet(), source_mode="fake") == ()
    assert flows.status_snapshot().active_flow_count == 1


def test_matching_metadata_updates_statistics():
    flows, _ = service()
    flows.accept(packet(length=10), source_mode="fake")
    flows.accept(packet(seconds=1, length=30), source_mode="fake")
    record = flows.flush()[0]
    assert (record.packet_count, record.total_bytes) == (2, 40)
    assert (record.minimum_packet_length, record.maximum_packet_length) == (10, 30)
    assert record.mean_packet_length == 20


def test_nonmatching_metadata_creates_separate_flow():
    flows, _ = service()
    flows.accept(packet(protocol="TCP"), source_mode="fake")
    flows.accept(packet(protocol="UDP"), source_mode="fake")
    assert flows.status_snapshot().active_flow_count == 2


def test_new_window_closes_old_window():
    flows, _ = service(aggregation_window_seconds=5)
    flows.accept(packet(seconds=1), source_mode="fake")
    completed = flows.accept(packet(seconds=5), source_mode="fake")
    assert completed[0].completed_reason is FlowCompletionReason.WINDOW_CLOSED


def test_inactivity_expiration():
    flows, mono = service(inactivity_timeout_seconds=10)
    flows.accept(packet(), source_mode="fake")
    mono[0] = 10
    assert flows.expire_inactive()[0].completed_reason is FlowCompletionReason.INACTIVITY_TIMEOUT


def test_duration_limit_starts_new_flow():
    flows, _ = service(aggregation_window_seconds=100, max_flow_duration_seconds=2)
    flows.accept(packet(), source_mode="fake")
    completed = flows.accept(packet(seconds=3), source_mode="fake")
    assert completed[0].completed_reason is FlowCompletionReason.DURATION_LIMIT_REACHED
    assert flows.status_snapshot().active_flow_count == 1


def test_packet_limit_finalizes_and_later_packet_starts_new():
    flows, _ = service(max_packets_per_flow=2)
    flows.accept(packet(), source_mode="fake")
    completed = flows.accept(packet(seconds=1), source_mode="fake")
    assert completed[0].completed_reason is FlowCompletionReason.PACKET_LIMIT_REACHED
    flows.accept(packet(seconds=2), source_mode="fake")
    assert flows.status_snapshot().active_flow_count == 1


def test_capacity_finalizes_least_recently_updated():
    flows, mono = service(max_active_flows=1)
    flows.accept(packet(interface="a"), source_mode="fake")
    mono[0] = 1
    completed = flows.accept(packet(interface="b"), source_mode="fake")
    assert completed[0].interface_key == "a"
    assert completed[0].completed_reason is FlowCompletionReason.ACTIVE_FLOW_CAPACITY


def test_completed_history_evicts_oldest():
    flows, _ = service(max_completed_flows=1)
    flows.accept(packet(interface="a"), source_mode="fake")
    flows.flush()
    flows.accept(packet(interface="b"), source_mode="fake")
    flows.flush()
    status = flows.status_snapshot()
    assert status.completed_flow_count == 1 and status.completed_flow_eviction_count == 1


def test_manual_and_session_flush():
    flows, _ = service()
    flows.accept(packet(interface="a"), source_mode="fake", capture_session_id="one")
    flows.accept(packet(interface="b"), source_mode="fake", capture_session_id="two")
    first = flows.flush(FlowCompletionReason.CAPTURE_SESSION_STOPPED, "one")
    assert len(first) == 1 and flows.status_snapshot().active_flow_count == 1
    assert flows.flush()[0].completed_reason is FlowCompletionReason.MANUAL_FLUSH


def test_thread_safe_snapshots():
    flows, _ = service(max_active_flows=100)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i: flows.accept(packet(interface=str(i)), source_mode="fake"), range(50)))
    assert flows.status_snapshot().active_flow_count == 50
    assert isinstance(flows.completed_snapshot(), tuple)
