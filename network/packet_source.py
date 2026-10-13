from __future__ import annotations

import datetime
from typing import Protocol, Optional, List, runtime_checkable

from .capture_models import CapturedPacketMetadata


@runtime_checkable
class PacketSource(Protocol):
    """Framework‑neutral protocol for any packet source implementation.

    All methods must be idempotent where appropriate and must not start
    background threads. The capture service owns the worker thread.
    """

    def list_interfaces(self) -> List[str]:
        """Return a list of native interface identifiers (e.g. "eth0")."""
        ...

    def open(self, native_interface: str, config) -> None:
        """Prepare the source for reading.

        ``config`` is the user‑provided capture configuration object.
        Implementations must raise ``CaptureInvalidInterfaceError`` for
        unknown interfaces and ``CaptureMissingDependencyError`` if a required
        backend library is unavailable.
        """
        ...

    def read_metadata(self, timeout: float) -> Optional[CapturedPacketMetadata]:
        """Attempt to read one packet's metadata within *timeout* seconds.

        Returns ``None`` on timeout or when no packet is available.
        Must never return raw packet objects.
        """
        ...

    def request_stop(self) -> None:
        """Signal the source that a graceful stop is requested.
        Implementations should make ``read_metadata`` return ``None``
        promptly after this call.
        """
        ...

    def close(self) -> None:
        """Release any resources held by the source. Idempotent."""
        ...

    def get_status(self) -> dict:
        """Return a status mapping useful for debugging (optional)."""
        ...
