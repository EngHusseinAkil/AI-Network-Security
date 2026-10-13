import pytest
from network.live_flow_evaluation_config import LiveFlowEvaluationConfig


def test_evaluation_config_defaults():
    config = LiveFlowEvaluationConfig()
    assert config.max_flows_per_request == 100
    assert config.max_retained_evaluations == 1000
    assert config.max_retry_count == 1
    assert config.schema_version == "live-flow-evaluation-v1"


@pytest.mark.parametrize("field", [
    "max_flows_per_request", "max_retained_evaluations", "max_retry_count"
])
def test_evaluation_config_rejects_booleans(field):
    with pytest.raises(ValueError):
        LiveFlowEvaluationConfig(**{field: True})


@pytest.mark.parametrize(("field", "value"), [
    ("max_flows_per_request", 0), ("max_flows_per_request", 1001),
    ("max_retained_evaluations", 0), ("max_retained_evaluations", 10001),
    ("max_retry_count", -1), ("max_retry_count", 11),
])
def test_evaluation_config_bounds(field, value):
    with pytest.raises(ValueError):
        LiveFlowEvaluationConfig(**{field: value})


@pytest.mark.parametrize("value", ["", " ", "x" * 65, "bad\nversion"])
def test_schema_version_validation(value):
    with pytest.raises(ValueError):
        LiveFlowEvaluationConfig(schema_version=value)
