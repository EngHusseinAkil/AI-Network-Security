"""Validated framework-neutral capture configuration."""
from dataclasses import dataclass
import math
from typing import Optional

DEFAULT_QUEUE_SIZE = 1024
CAPTURE_QUEUE_SIZE_MIN = 1
CAPTURE_QUEUE_SIZE_MAX = 10_000
CAPTURE_FILTER_MAX_LENGTH = 256


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    enabled: bool = False
    source: str = "scapy"
    fake_source_permitted: bool = False
    max_packets: Optional[int] = None
    max_duration_seconds: Optional[float] = None
    queue_size: int = DEFAULT_QUEUE_SIZE
    capture_filter: Optional[str] = None
    promiscuous: bool = True
    read_timeout_seconds: float = 1.0
    stop_join_timeout_seconds: float = 5.0

    def __post_init__(self):
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a boolean")
        if not isinstance(self.fake_source_permitted, bool):
            raise ValueError("fake_source_permitted must be a boolean")
        if self.source not in ("scapy", "fake"):
            raise ValueError("source must be scapy or fake")
        if self.source == "fake" and not self.fake_source_permitted:
            raise ValueError("fake source is not permitted")
        self._integer("queue_size", self.queue_size, 1, 10_000)
        if self.max_packets is not None:
            self._integer("max_packets", self.max_packets, 1)
        self._number("max_duration_seconds", self.max_duration_seconds)
        self._number("read_timeout_seconds", self.read_timeout_seconds, required=True)
        self._number("stop_join_timeout_seconds", self.stop_join_timeout_seconds, required=True)
        if not isinstance(self.promiscuous, bool):
            raise ValueError("promiscuous must be a boolean")
        if self.capture_filter is not None:
            if not isinstance(self.capture_filter, str):
                raise ValueError("capture_filter must be a string")
            value = self.capture_filter.strip()
            if not value:
                object.__setattr__(self, "capture_filter", None)
            elif (len(value) > CAPTURE_FILTER_MAX_LENGTH
                  or any(ord(ch) < 32 or ord(ch) == 127 for ch in self.capture_filter)):
                raise ValueError("capture_filter is unsafe or too long")
            else:
                object.__setattr__(self, "capture_filter", value)

    @staticmethod
    def _integer(name, value, minimum, maximum=None):
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise ValueError(f"{name} must be an integer of at least {minimum}")
        if maximum is not None and value > maximum:
            raise ValueError(f"{name} exceeds {maximum}")

    @staticmethod
    def _number(name, value, required=False):
        if value is None and not required:
            return
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value) or value <= 0):
            raise ValueError(f"{name} must be finite and positive")

    def limits_snapshot(self):
        from .capture_models import CaptureLimitsSnapshot
        return CaptureLimitsSnapshot(
            self.max_packets, self.max_duration_seconds, self.queue_size,
            float(self.read_timeout_seconds), float(self.stop_join_timeout_seconds)
        )

    limits_dict = limits_snapshot
