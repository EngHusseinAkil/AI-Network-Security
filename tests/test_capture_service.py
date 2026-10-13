from datetime import datetime, timezone
import threading
import time
import pytest

from network.capture_config import CaptureConfig
from network.capture_exceptions import (
    CaptureAlreadyRunningError, CaptureDisabledError, CaptureNotRunningError,
    CaptureStopTimeoutError,
)
from network.capture_models import CapturedPacketMetadata, FlowEndpointMetadata
from network.capture_service import CaptureService
from network.constants import CaptureState
from network.fake_source import FakePacketSource


class Discovery:
    def resolve(self, key):
        if key != "key":
            raise ValueError
        return "native"


class ShutdownInterruptedSource(FakePacketSource):
    """Source that models a blocking native read interrupted by shutdown."""

    def __init__(self):
        super().__init__(repeat=True)
        self.read_started = threading.Event()
        self.release_read = threading.Event()

    def read_metadata(self, timeout):
        self.read_started.set()
        self.release_read.wait(timeout=1)
        if self._stopped:
            raise OSError("Npcap adapter closed during stop")
        return None

    def request_stop(self):
        super().request_stop()
        self.release_read.set()


class FailingSource(FakePacketSource):
    def read_metadata(self, timeout):
        raise OSError("pcap read failure: interface disappeared")


class NonIpThenMetadataSource(FakePacketSource):
    def __init__(self):
        super().__init__([metadata()], repeat=False)
        self.non_ip_reads = 0

    def read_metadata(self, timeout):
        if self.non_ip_reads < 5:
            self.non_ip_reads += 1
            return None
        return super().read_metadata(timeout)


def metadata():
    return CapturedPacketMetadata(datetime.now(timezone.utc), 10, "tcp", "key")


def build(config=None, source=None, clock=None):
    config = config or CaptureConfig(enabled=True, read_timeout_seconds=.01)
    source = source or FakePacketSource([metadata()], repeat=True)
    return CaptureService(config, lambda cfg, native, key: source, Discovery(), clock=clock), source


def wait_state(service, state, timeout=1):
    deadline = time.time() + timeout
    while service.status_snapshot().state is not state and time.time() < deadline:
        time.sleep(.005)
    return service.status_snapshot()


def test_disabled_start():
    service = CaptureService(CaptureConfig(), None, Discovery())
    with pytest.raises(CaptureDisabledError):
        service.start_capture("key")


def test_valid_start_and_stop_one_non_daemon_worker():
    service, source = build()
    service.start_capture("key")
    worker = service._worker
    assert worker.is_alive() and not worker.daemon
    service.stop_capture()
    assert service.status_snapshot().state is CaptureState.STOPPED
    assert service._worker is None and service._source is None and source.get_status()["closed"]


def test_manual_stop_ignores_expected_worker_read_interruption(caplog):
    source = ShutdownInterruptedSource()
    service, _ = build(source=source)
    service.start_capture("key")
    assert source.read_started.wait(1)

    service.stop_capture()

    status = service.status_snapshot()
    assert status.state is CaptureState.STOPPED
    assert status.stop_reason == "user_requested"
    assert status.error_category is None
    assert "Npcap adapter closed during stop" in caplog.text


def test_source_exception_while_running_is_visible():
    service, _ = build(source=FailingSource())
    service.start_capture("key")

    status = wait_state(service, CaptureState.ERROR)
    assert status.stop_reason == "source_error"
    assert status.error_category == "capture_failed"


def test_repeated_unsupported_packets_do_not_transition_capture_to_error():
    source = NonIpThenMetadataSource()
    service, _ = build(
        CaptureConfig(enabled=True, max_packets=1, read_timeout_seconds=.01), source
    )
    service.start_capture("key")

    status = wait_state(service, CaptureState.STOPPED)
    assert status.state is CaptureState.STOPPED
    assert status.error_category is None
    assert source.non_ip_reads == 5


def test_selected_device_filter_drops_unselected_local_endpoint():
    selected = CapturedPacketMetadata(
        datetime.now(timezone.utc), 10, "tcp", "key", endpoint_metadata=FlowEndpointMetadata(
            "192.168.137.17", "8.8.8.8"
        )
    )
    unselected = CapturedPacketMetadata(
        datetime.now(timezone.utc), 10, "tcp", "key", endpoint_metadata=FlowEndpointMetadata(
            "192.168.137.16", "8.8.8.8"
        )
    )
    service, _ = build(
        CaptureConfig(enabled=True, max_packets=1, read_timeout_seconds=.01),
        FakePacketSource([unselected, selected]),
    )
    service.start_capture("key", {"192.168.137.17"})
    status = wait_state(service, CaptureState.STOPPED)
    assert status.packet_count == 1
    assert service.drain_metadata(2)[0].endpoint_metadata.source_ip == "192.168.137.17"


def test_successful_stop_remains_stopped_during_repeated_polling():
    service, _ = build()
    service.start_capture("key")
    service.stop_capture()

    for _ in range(10):
        assert service.status_snapshot().state is CaptureState.STOPPED


def test_duplicate_start_and_stop():
    service, _ = build()
    service.start_capture("key")
    with pytest.raises(CaptureAlreadyRunningError):
        service.start_capture("key")
    service.stop_capture()
    with pytest.raises(CaptureNotRunningError):
        service.stop_capture()


def test_packet_limit_is_normal_stop():
    service, _ = build(CaptureConfig(enabled=True, max_packets=2, read_timeout_seconds=.01))
    service.start_capture("key")
    status = wait_state(service, CaptureState.STOPPED)
    assert status.stop_reason == "packet_limit_reached" and status.error_category is None


def test_duration_limit_is_normal_stop():
    clock = [0.0]
    def advance():
        clock[0] += .6
        return clock[0]
    service, _ = build(CaptureConfig(enabled=True, max_duration_seconds=1,
                                     read_timeout_seconds=.01), clock=advance)
    service.start_capture("key")
    assert wait_state(service, CaptureState.STOPPED).stop_reason == "duration_limit_reached"


def test_queue_overflow_drops_new_record():
    service, _ = build(CaptureConfig(enabled=True, max_packets=3, queue_size=1,
                                     read_timeout_seconds=.01))
    service.start_capture("key")
    status = wait_state(service, CaptureState.STOPPED)
    assert status.packet_count == 3 and status.dropped_metadata_count == 2


def test_snapshot_and_drain_contract():
    service, _ = build(CaptureConfig(enabled=True, max_packets=2, read_timeout_seconds=.01))
    service.start_capture("key")
    wait_state(service, CaptureState.STOPPED)
    assert len(service.get_metadata_snapshot(1)) == 1
    assert len(service.get_metadata_snapshot(2)) == 2
    assert len(service.drain_metadata(1)) == 1
    assert len(service.get_metadata_snapshot(2)) == 1


@pytest.mark.parametrize("method", ["get_metadata_snapshot", "drain_metadata"])
@pytest.mark.parametrize("limit", [0, -1, True, 1.2])
def test_invalid_queue_limit(method, limit):
    service, _ = build()
    with pytest.raises(ValueError):
        getattr(service, method)(limit)


def test_stop_timeout_retains_ownership_and_retry_cleans():
    gate = threading.Event()
    source = FakePacketSource([metadata()], blocking_event=gate)
    service, _ = build(CaptureConfig(enabled=True, read_timeout_seconds=.01,
                                     stop_join_timeout_seconds=.01), source)
    service.start_capture("key")
    with pytest.raises(CaptureStopTimeoutError):
        service.stop_capture()
    assert service._worker is not None and service._source is source
    assert service.status_snapshot().error_category == "stop_timeout"
    with pytest.raises(CaptureAlreadyRunningError):
        service.start_capture("key")
    gate.set()
    time.sleep(.02)
    service.stop_capture()
    assert service._worker is None and service._source is None


def test_safe_summary():
    service, _ = build(CaptureConfig(enabled=True, max_packets=1, read_timeout_seconds=.01))
    service.start_capture("key")
    wait_state(service, CaptureState.STOPPED)
    summary = service.final_summary()
    assert summary.interface_key == "key" and summary.final_state is CaptureState.STOPPED
