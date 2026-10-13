from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
import threading
import time

from backend.services.live_flow_evaluation_service import LiveFlowEvaluationService
from network.flow_models import (
    FeatureExtractionResult, FlowCompletionReason, MetadataFlowRecord,
    NetworkFeatureVector,
)
from network.live_flow_evaluation_config import LiveFlowEvaluationConfig
from network.live_flow_evaluation_state import LiveFlowEvaluationStateService


def flow(flow_id="flow", packet_count=2):
    now = datetime.now(timezone.utc)
    return MetadataFlowRecord(
        flow_id, "opaque", "TCP", "unknown", now, now, 1, packet_count, 20,
        10, 10, 10, FlowCompletionReason.MANUAL_FLUSH, "fake", None,
    )


class Provider:
    def __init__(self, flows):
        self.flows = tuple(flows)
    def completed_snapshot(self):
        return self.flows


class Feature:
    def __init__(self, compatible=True, calls=None):
        self.compatible, self.calls = compatible, calls
    def extract(self, value):
        if self.calls is not None:
            self.calls.append("feature")
        if not self.compatible or value.packet_count == 0:
            return FeatureExtractionResult(False, None, "empty_flow")
        return FeatureExtractionResult(
            True, NetworkFeatureVector(1, 2, 20, 10, 10, 10, 1, 0), None
        )


class Inference:
    def __init__(self, calls=None, version="model-v1"):
        self.calls, self.version = calls, version
        self.fail = False
    def get_model_info(self):
        return {"model_version": self.version}
    def predict_flow(self, features):
        if self.calls is not None:
            self.calls.append("inference")
        if self.fail:
            raise RuntimeError
        return {
            "predicted_canonical_label": "benign", "confidence_score": .9,
            "risk_score": .1, "model_version": self.version,
        }


class Policy:
    VERSION = "1.0.0"
    def __init__(self, calls=None):
        self.calls, self.fail, self.last_input = calls, False, None
    def evaluate(self, value):
        if self.calls is not None:
            self.calls.append("policy")
        self.last_input = value
        if self.fail:
            raise RuntimeError
        return SimpleNamespace(
            should_create_alert=False, proposed_type=None, proposed_severity=None,
            reason_code=SimpleNamespace(value="benign_prediction"),
            policy_version=self.VERSION,
        )


def build(flows, feature=None, inference=None, policy=None, state=None, config=None):
    config = config or LiveFlowEvaluationConfig()
    state = state or LiveFlowEvaluationStateService(config)
    service = LiveFlowEvaluationService(
        Provider(flows), feature or Feature(), inference or Inference(),
        policy or Policy(), state, config, utc_clock=lambda: datetime.now(timezone.utc),
    )
    return service, state


def test_call_order_and_exact_policy_context():
    calls = []
    policy = Policy(calls)
    service, state = build([flow()], Feature(calls=calls), Inference(calls), policy)
    service.evaluate()
    assert calls == ["feature", "inference", "policy"]
    assert policy.last_input.source_category == "live_metadata_flow"
    assert policy.last_input.occurrence_count == 1
    assert state.snapshot().retained_evaluation_count == 1


def test_incompatible_skips_inference_and_policy():
    inference, policy = Inference(), Policy()
    inference.predict_flow = Mock()
    policy.evaluate = Mock()
    service, state = build([flow(packet_count=0)], Feature(False), inference, policy)
    service.evaluate()
    inference.predict_flow.assert_not_called()
    policy.evaluate.assert_not_called()
    assert state.snapshot().incompatible_flow_count == 1


def test_inference_failure_skips_policy_and_later_flow_continues():
    inference, policy = Inference(), Policy()
    original = inference.predict_flow
    count = [0]
    def sometimes(features):
        count[0] += 1
        if count[0] == 1:
            raise RuntimeError
        return original(features)
    inference.predict_flow = sometimes
    service, state = build([flow("one"), flow("two")], inference=inference, policy=policy)
    service.evaluate()
    snapshot = state.snapshot()
    assert snapshot.failed_inference_count == 1
    assert snapshot.successful_inference_count == 1
    assert snapshot.successful_policy_count == 1


def test_policy_failure_preserves_inference():
    policy = Policy(); policy.fail = True
    service, state = build([flow()], policy=policy)
    service.evaluate()
    record = state.snapshot().latest_record
    assert record.inference_status == "success"
    assert record.policy_status == "failed"
    assert record.safe_error_category == "policy_unavailable"
    assert not record.alert_recommended


def test_duplicate_success_skipped():
    service, state = build([flow()])
    service.evaluate(); service.evaluate()
    snapshot = state.snapshot()
    assert snapshot.retained_evaluation_count == 1
    assert snapshot.flows_skipped_already_evaluated_count == 1


def test_failed_evaluation_can_retry():
    inference = Inference(); inference.fail = True
    service, state = build([flow()], inference=inference)
    service.evaluate()
    inference.fail = False
    service.evaluate()
    assert state.snapshot().retained_evaluation_count == 2
    assert state.snapshot().latest_record.successful


def test_version_changes_permit_reevaluation():
    inference, policy = Inference(), Policy()
    service, state = build([flow()], inference=inference, policy=policy)
    service.evaluate()
    inference.version = "model-v2"
    service.evaluate()
    policy.VERSION = "2.0.0"
    service.evaluate()
    assert state.snapshot().retained_evaluation_count == 3


def test_evaluation_schema_change_permits_reevaluation():
    state = LiveFlowEvaluationStateService(LiveFlowEvaluationConfig())
    first, _ = build([flow()], state=state)
    first.evaluate()
    second, _ = build(
        [flow()], state=state,
        config=LiveFlowEvaluationConfig(schema_version="live-flow-evaluation-v2"),
    )
    second.evaluate()
    assert state.snapshot().retained_evaluation_count == 2


def test_batch_is_server_bounded_and_ordered():
    service, state = build(
        [flow(str(i)) for i in range(5)],
        config=LiveFlowEvaluationConfig(max_flows_per_request=2),
    )
    result = service.evaluate()
    assert result.considered_count == 2
    assert [r.flow_id for r in state.snapshot().recent_records] == ["0", "1"]


def test_concurrent_duplicate_retains_one_success():
    inference = Inference()
    original = inference.predict_flow
    inference.predict_flow = lambda features: (time.sleep(.03), original(features))[1]
    service, state = build([flow()], inference=inference)
    threads = [threading.Thread(target=service.evaluate) for _ in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert state.snapshot().retained_evaluation_count == 1


def test_exception_does_not_leave_stuck_reservation():
    service, state = build([flow()])
    service._evaluate_one = Mock(side_effect=RuntimeError)
    service.evaluate()
    key = service.build_evaluation_key(
        "flow", "metadata-flow-v1", "model-v1", "1.0.0",
        "live-flow-evaluation-v1",
    )
    assert state.reserve(key)
