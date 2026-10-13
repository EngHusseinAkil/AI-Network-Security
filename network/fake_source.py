"""Deterministic thread-free packet source for tests and explicit demos."""
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
import threading

from .capture_models import CapturedPacketMetadata


def deterministic_demo_metadata(*, interface_key: str) -> tuple[CapturedPacketMetadata, ...]:
    """Return the bounded, payload-free metadata fixture used by the local demo."""
    start = datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc)
    return tuple(
        CapturedPacketMetadata(
            timestamp=start + timedelta(seconds=index * 0.01),
            packet_length=64,
            protocol="TCP",
            interface_key=interface_key,
            direction="outbound",
        )
        for index in range(20)
    )


def metadata_for_config(app_config, capture_config, interface_key: str):
    """Enable the fixture only for the explicitly gated development demo."""
    if (
        app_config.get("ENVIRONMENT") == "development"
        and app_config.get("DEMO_MODE") is True
        and capture_config.source == "fake"
        and capture_config.fake_source_permitted
    ):
        return deterministic_demo_metadata(interface_key=interface_key)
    return ()


class FakePacketSource:
    def __init__(self, metadata: Iterable[CapturedPacketMetadata] = (), *,
                 repeat=False, delay=None, blocking_event: threading.Event | None = None):
        self._items = tuple(metadata)
        self._repeat, self._delay, self._blocking_event = repeat, delay, blocking_event
        self._index = 0
        self._stopped = self._closed = self._open = False

    def list_interfaces(self):
        return ["fake0"]

    def open(self, native_interface, config):
        self._open = True

    def read_metadata(self, timeout):
        if self._blocking_event is not None:
            self._blocking_event.wait()
        if self._stopped or self._closed or not self._items:
            if not self._stopped and not self._closed:
                threading.Event().wait(timeout)
            return None
        if self._index >= len(self._items):
            if not self._repeat:
                threading.Event().wait(timeout)
                return None
            self._index = 0
        if self._delay:
            self._delay(timeout)
        item = self._items[self._index]
        self._index += 1
        return item

    def request_stop(self):
        self._stopped = True

    def close(self):
        self._closed = True

    def get_status(self):
        return {"open": self._open, "stopped": self._stopped, "closed": self._closed}
