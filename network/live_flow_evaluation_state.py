"""Lock-owned bounded evaluation history, replay index, and counters."""
from collections import deque
import threading
from dataclasses import replace

from .live_flow_evaluation_models import LiveFlowEvaluationSnapshot


class LiveFlowEvaluationStateService:
    def __init__(self, config):
        self._config = config
        self._lock = threading.RLock()
        self._history = deque()
        self._successful = {}
        self._attempts = {}
        self._reservations = set()
        self._counters = {
            "evaluation_request_count": 0,
            "flows_considered_count": 0,
            "flows_skipped_already_evaluated_count": 0,
            "incompatible_flow_count": 0,
            "successful_inference_count": 0,
            "failed_inference_count": 0,
            "successful_policy_count": 0,
            "failed_policy_count": 0,
            "recommendation_count": 0,
            "evaluation_eviction_count": 0,
        }

    def begin_request(self):
        with self._lock:
            self._counters["evaluation_request_count"] += 1

    def reserve(self, key):
        with self._lock:
            self._counters["flows_considered_count"] += 1
            if key in self._successful or key in self._reservations:
                self._counters["flows_skipped_already_evaluated_count"] += 1
                return False
            if self._attempts.get(key, 0) > self._config.max_retry_count:
                self._counters["flows_skipped_already_evaluated_count"] += 1
                return False
            self._reservations.add(key)
            return True

    def release(self, key):
        with self._lock:
            self._reservations.discard(key)

    def retain(self, record):
        with self._lock:
            self._reservations.discard(record.evaluation_key)
            self._attempts[record.evaluation_key] = self._attempts.get(record.evaluation_key, 0) + 1
            if record.successful and record.evaluation_key in self._successful:
                self._counters["flows_skipped_already_evaluated_count"] += 1
                return False
            if len(self._history) >= self._config.max_retained_evaluations:
                evicted = self._history.popleft()
                if self._successful.get(evicted.evaluation_key) is evicted:
                    self._successful.pop(evicted.evaluation_key, None)
                if not any(item.evaluation_key == evicted.evaluation_key for item in self._history):
                    self._attempts.pop(evicted.evaluation_key, None)
                self._counters["evaluation_eviction_count"] += 1
            self._history.append(record)
            if record.successful:
                self._successful[record.evaluation_key] = record
            if not record.feature_compatible:
                self._counters["incompatible_flow_count"] += 1
            if record.inference_status == "success":
                self._counters["successful_inference_count"] += 1
            elif record.inference_status == "failed":
                self._counters["failed_inference_count"] += 1
            if record.policy_status == "success":
                self._counters["successful_policy_count"] += 1
            elif record.policy_status == "failed":
                self._counters["failed_policy_count"] += 1
            if record.alert_recommended:
                self._counters["recommendation_count"] += 1
            return True

    def snapshot(self, recent_limit=20):
        with self._lock:
            recent = tuple(self._history)[-recent_limit:]
            return LiveFlowEvaluationSnapshot(
                **self._counters,
                retained_evaluation_count=len(self._history),
                successfully_evaluated_flow_count=len({
                    record.flow_id for record in self._history if record.successful
                }),
                latest_record=self._history[-1] if self._history else None,
                recent_records=recent,
            )

    def is_successfully_evaluated(self, key):
        with self._lock:
            return key in self._successful

    def get_record(self, evaluation_id):
        with self._lock:
            return next(
                (record for record in self._history if record.evaluation_id == evaluation_id),
                None,
            )

    def mark_alert_persisted(self, evaluation_id, alert_id, created_at):
        with self._lock:
            for index, record in enumerate(self._history):
                if record.evaluation_id == evaluation_id:
                    updated = replace(
                        record, alert_persisted=True,
                        persisted_alert_id=alert_id, alert_created_at=created_at,
                    )
                    self._history[index] = updated
                    if self._successful.get(record.evaluation_key) is record:
                        self._successful[record.evaluation_key] = updated
                    return updated
            return None
