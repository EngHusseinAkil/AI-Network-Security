"""Framework-neutral bounds for explicit metadata-flow evaluation."""
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LiveFlowEvaluationConfig:
    max_flows_per_request: int = 100
    max_retained_evaluations: int = 1_000
    max_retry_count: int = 1
    schema_version: str = "live-flow-evaluation-v1"

    def __post_init__(self):
        self._integer("max_flows_per_request", self.max_flows_per_request, 1, 1_000)
        self._integer("max_retained_evaluations", self.max_retained_evaluations, 1, 10_000)
        self._integer("max_retry_count", self.max_retry_count, 0, 10)
        if (not isinstance(self.schema_version, str)
                or not self.schema_version.strip()
                or len(self.schema_version) > 64
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in self.schema_version)):
            raise ValueError("schema_version must be a bounded printable token")

    @staticmethod
    def _integer(name, value, minimum, maximum):
        if (not isinstance(value, int) or isinstance(value, bool)
                or not minimum <= value <= maximum):
            raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
