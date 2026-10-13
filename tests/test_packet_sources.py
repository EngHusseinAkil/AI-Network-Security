from datetime import datetime, timezone
import sys
import threading

from network.capture_config import CaptureConfig
from network.capture_models import CapturedPacketMetadata
from network.fake_source import FakePacketSource
from network.packet_source import PacketSource


def item(length=1):
    return CapturedPacketMetadata(datetime.now(timezone.utc), length, "tcp", "key")


def test_fake_deterministic_output_and_exhaustion():
    source = FakePacketSource([item(1), item(2)])
    source.open("fake0", CaptureConfig())
    assert [source.read_metadata(0).packet_length for _ in range(2)] == [1, 2]
    assert source.read_metadata(0) is None


def test_fake_repeat():
    source = FakePacketSource([item()], repeat=True)
    source.open("fake0", CaptureConfig())
    assert source.read_metadata(0) == source.read_metadata(0)


def test_fake_blocking_control():
    gate = threading.Event()
    source = FakePacketSource([item()], blocking_event=gate)
    source.open("fake0", CaptureConfig())
    thread = threading.Thread(target=source.read_metadata, args=(0,))
    thread.start()
    assert thread.is_alive()
    gate.set()
    thread.join(1)


def test_fake_protocol_compliance():
    assert isinstance(FakePacketSource(), PacketSource)


def test_fake_import_does_not_load_scapy():
    assert "scapy" not in sys.modules


def test_stop_and_close_idempotent():
    source = FakePacketSource()
    source.request_stop(); source.request_stop(); source.close(); source.close()
    assert source.get_status()["closed"]


def test_source_owns_no_worker_thread():
    assert not hasattr(FakePacketSource(), "_worker")
