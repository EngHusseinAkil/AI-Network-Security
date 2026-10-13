"""Validated bounds for metadata-only flow aggregation."""
from dataclasses import dataclass
import math


@dataclass(frozen=True, slots=True)
class MetadataFlowConfig:
    aggregation_window_seconds: float = 5.0
    inactivity_timeout_seconds: float = 10.0
    max_active_flows: int = 1_000
    max_completed_flows: int = 1_000
    max_packets_per_flow: int = 10_000
    max_flow_duration_seconds: float = 60.0
    max_processing_batch: int = 1_024

    def __post_init__(self):
        self._number("aggregation_window_seconds", self.aggregation_window_seconds, 0.001, 3_600)
        self._number("inactivity_timeout_seconds", self.inactivity_timeout_seconds, 0.001, 3_600)
        self._integer("max_active_flows", self.max_active_flows, 1, 10_000)
        self._integer("max_completed_flows", self.max_completed_flows, 1, 10_000)
        self._integer("max_packets_per_flow", self.max_packets_per_flow, 1, 1_000_000)
        self._number("max_flow_duration_seconds", self.max_flow_duration_seconds, 0.001, 3_600)
        self._integer("max_processing_batch", self.max_processing_batch, 1, 10_000)

    @staticmethod
    def _number(name, value, minimum, maximum):
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value) or not minimum <= value <= maximum):
            raise ValueError(f"{name} must be finite and between {minimum} and {maximum}")

    @staticmethod
    def _integer(name, value, minimum, maximum):
        if (not isinstance(value, int) or isinstance(value, bool)
                or not minimum <= value <= maximum):
            raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
