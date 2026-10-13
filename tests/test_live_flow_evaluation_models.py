from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import math
import pytest

from network.live_flow_evaluation_models import LiveFlowEvaluationRecord


def record(**changes):
    values = dict(
        evaluation_id="evaluation", evaluation_key="internal-key", flow_id="flow",
        flow_schema_version="metadata-flow-v1",
        evaluated_at=datetime.now(timezone.utc), feature_compatible=True,
        inference_status="success", predicted_canonical_label="benign",
        confidence_score=.9, risk_score=.1, model_version="model-v1",
        policy_status="success", alert_recommended=False,
        proposed_alert_type=None, proposed_severity=None, reason_code="benign_prediction",
        policy_version="1.0.0", source_category="live_metadata_flow",
        safe_error_category=None, evaluation_schema_version="live-flow-evaluation-v1",
    )
    values.update(changes)
    return LiveFlowEvaluationRecord(**values)


def test_record_is_frozen():
    value = record()
    with pytest.raises(FrozenInstanceError):
        value.policy_status = "failed"


def test_timestamp_normalized_to_utc():
    offset = timezone(timedelta(hours=3))
    assert record(evaluated_at=datetime.now(offset)).evaluated_at.tzinfo is timezone.utc


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        record(evaluated_at=datetime.now())


@pytest.mark.parametrize(("field", "value"), [
    ("confidence_score", math.nan), ("confidence_score", 1.1),
    ("risk_score", math.inf), ("risk_score", -0.1),
])
def test_scores_finite_and_bounded(field, value):
    with pytest.raises(ValueError):
        record(**{field: value})


def test_side_effect_flags_must_remain_false():
    with pytest.raises(ValueError):
        record(alert_persisted=True)


def test_no_sensitive_record_fields():
    names = {field.name for field in fields(LiveFlowEvaluationRecord)}
    assert names.isdisjoint({
        "raw_flow", "features", "native_interface", "packet", "payload",
        "model_path", "registry_path", "estimator", "exception",
        "recommendation_token", "deduplication_key", "session", "csrf",
    })


def test_exact_source_category():
    assert record().source_category == "live_metadata_flow"
