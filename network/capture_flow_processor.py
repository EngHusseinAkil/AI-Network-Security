"""Explicit bounded consumer from capture queue to metadata-flow aggregation.

Drained records are removed from the capture queue. Invalid records are not
reinserted; processing continues because each aggregate update is atomic.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import threading

from .constants import CaptureState
from .flow_models import FlowCompletionReason


@dataclass(frozen=True, slots=True)
class FlowProcessingSnapshot:
    metadata_records_drained: int
    metadata_records_processed: int
    metadata_processing_failures: int
    feature_vectors_created: int
    incompatible_flow_count: int
    last_processing_timestamp: datetime | None
    last_safe_error_category: str | None


class CaptureFlowProcessor:
    def __init__(self, capture_service, aggregation_service, feature_service, config,
                 utc_clock=None):
        self._capture = capture_service
        self._aggregation = aggregation_service
        self._features = feature_service
        self._config = config
        self._utc = utc_clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._drained = self._processed = self._failures = 0
        self._feature_count = self._incompatible = 0
        self._last_timestamp = self._last_error = None

    def process(self):
        records = self._capture.drain_metadata(self._config.max_processing_batch)
        capture = self._capture.status_snapshot()
        created = []
        failures = 0
        for metadata in records:
            try:
                completed = self._aggregation.accept(
                    metadata, source_mode=capture.source,
                    capture_session_id=capture.session_id,
                )
                created.extend(completed)
            except Exception:
                failures += 1
        if capture.state is CaptureState.STOPPED and capture.session_id:
            created.extend(self._aggregation.flush(
                FlowCompletionReason.CAPTURE_SESSION_STOPPED, capture.session_id
            ))
        compatible = incompatible = 0
        for flow in created:
            result = self._features.extract(flow)
            if result.compatible:
                compatible += 1
            else:
                incompatible += 1
        with self._lock:
            self._drained += len(records)
            self._processed += len(records) - failures
            self._failures += failures
            self._feature_count += compatible
            self._incompatible += incompatible
            self._last_timestamp = self._utc()
            self._last_error = "metadata_processing_failed" if failures else None
        return tuple(created)

    def status_snapshot(self):
        with self._lock:
            return FlowProcessingSnapshot(
                self._drained, self._processed, self._failures,
                self._feature_count, self._incompatible,
                self._last_timestamp, self._last_error,
            )
