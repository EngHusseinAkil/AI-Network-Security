from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from network.live_flow_evaluation_config import LiveFlowEvaluationConfig
from network.live_flow_evaluation_models import LiveFlowEvaluationRecord
from network.live_flow_evaluation_state import LiveFlowEvaluationStateService


def record(key="key", evaluation_id="id", success=True):
    return LiveFlowEvaluationRecord(
        evaluation_id, key, "flow-" + evaluation_id, "metadata-flow-v1",
        datetime.now(timezone.utc), True,
        "success" if success else "failed", "benign" if success else None,
        .9 if success else None, .1 if success else None, "model",
        "success" if success else "not_run", False, None, None,
        "benign_prediction" if success else None, "1.0.0",
        "live_metadata_flow", None if success else "inference_unavailable",
        "live-flow-evaluation-v1",
    )


def test_reservation_prevents_duplicate():
    state = LiveFlowEvaluationStateService(LiveFlowEvaluationConfig())
    assert state.reserve("key")
    assert not state.reserve("key")
    state.release("key")
    assert state.reserve("key")


def test_successful_record_prevents_replay():
    state = LiveFlowEvaluationStateService(LiveFlowEvaluationConfig())
    state.reserve("key")
    assert state.retain(record())
    assert state.is_successfully_evaluated("key")
    assert not state.reserve("key")


def test_failed_record_allows_one_retry():
    state = LiveFlowEvaluationStateService(LiveFlowEvaluationConfig(max_retry_count=1))
    state.reserve("key"); state.retain(record(success=False))
    assert state.reserve("key")
    state.retain(record(evaluation_id="retry", success=False))
    assert not state.reserve("key")


def test_bounded_history_evicts_oldest_and_cleans_index():
    state = LiveFlowEvaluationStateService(
        LiveFlowEvaluationConfig(max_retained_evaluations=1)
    )
    state.reserve("one"); state.retain(record("one", "one"))
    state.reserve("two"); state.retain(record("two", "two"))
    snapshot = state.snapshot()
    assert [item.evaluation_id for item in snapshot.recent_records] == ["two"]
    assert snapshot.evaluation_eviction_count == 1
    assert state.reserve("one")


def test_snapshot_is_immutable_tuple_and_counters_accurate():
    state = LiveFlowEvaluationStateService(LiveFlowEvaluationConfig())
    state.begin_request()
    state.reserve("key"); state.retain(record())
    snapshot = state.snapshot()
    assert snapshot.evaluation_request_count == 1
    assert snapshot.flows_considered_count == 1
    assert snapshot.successful_inference_count == 1
    assert snapshot.successful_policy_count == 1
    assert isinstance(snapshot.recent_records, tuple)


def test_concurrent_reservation_has_single_winner():
    state = LiveFlowEvaluationStateService(LiveFlowEvaluationConfig())
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: state.reserve("same"), range(20)))
    assert results.count(True) == 1
