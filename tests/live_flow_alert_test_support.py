from datetime import datetime, timezone
import threading

from network.live_flow_evaluation_config import LiveFlowEvaluationConfig
from network.live_flow_evaluation_models import LiveFlowEvaluationRecord
from network.live_flow_evaluation_state import LiveFlowEvaluationStateService


def eligible_record(evaluation_id="evaluation-1", **changes):
    values = {
        "evaluation_id": evaluation_id,
        "evaluation_key": "private-key-" + evaluation_id,
        "flow_id": "flow-" + evaluation_id,
        "flow_schema_version": "metadata-flow-v1",
        "evaluated_at": datetime.now(timezone.utc),
        "feature_compatible": True,
        "inference_status": "success",
        "predicted_canonical_label": "ddos",
        "confidence_score": 0.91,
        "risk_score": 0.88,
        "model_version": "model-v1",
        "policy_status": "success",
        "alert_recommended": True,
        "proposed_alert_type": "suspected_ddos",
        "proposed_severity": "high",
        "reason_code": "risk_threshold_met",
        "policy_version": "policy-v1",
        "source_category": "live_metadata_flow",
        "safe_error_category": None,
        "evaluation_schema_version": "live-flow-evaluation-v1",
    }
    values.update(changes)
    return LiveFlowEvaluationRecord(**values)


def retained_state(record=None):
    state = LiveFlowEvaluationStateService(LiveFlowEvaluationConfig())
    state.retain(record or eligible_record())
    return state


class MemoryPersistence:
    def __init__(self):
        self.alerts = {}
        self.stored = []
        self.lock = threading.Lock()
        self.failure = None

    def find_by_deduplication_key(self, key):
        return self.alerts.get(key)

    def store_alert(self, alert, policy_version, reason_code):
        if self.failure:
            raise self.failure
        with self.lock:
            existing = self.alerts.get(alert.deduplication_key)
            if existing:
                from utils.exceptions import ConflictError
                raise ConflictError("duplicate")
            result = {"public_alert_id": alert.alert_id}
            self.alerts[alert.deduplication_key] = result
            self.stored.append((alert, policy_version, reason_code))
            return result
