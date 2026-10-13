import math
import pytest
from network.flow_config import MetadataFlowConfig


def test_flow_config_defaults():
    config = MetadataFlowConfig()
    assert (config.aggregation_window_seconds, config.inactivity_timeout_seconds) == (5, 10)
    assert (config.max_active_flows, config.max_completed_flows) == (1000, 1000)
    assert (config.max_packets_per_flow, config.max_flow_duration_seconds) == (10000, 60)


@pytest.mark.parametrize("field", [
    "aggregation_window_seconds", "inactivity_timeout_seconds",
    "max_active_flows", "max_completed_flows", "max_packets_per_flow",
    "max_flow_duration_seconds", "max_processing_batch",
])
def test_flow_config_rejects_booleans(field):
    with pytest.raises(ValueError):
        MetadataFlowConfig(**{field: True})


@pytest.mark.parametrize("field", [
    "aggregation_window_seconds", "inactivity_timeout_seconds",
    "max_flow_duration_seconds",
])
@pytest.mark.parametrize("value", [0, -1, math.nan, math.inf])
def test_flow_duration_bounds(field, value):
    with pytest.raises(ValueError):
        MetadataFlowConfig(**{field: value})


@pytest.mark.parametrize(("field", "value"), [
    ("max_active_flows", 0), ("max_active_flows", 10001),
    ("max_completed_flows", 0), ("max_completed_flows", 10001),
    ("max_processing_batch", 10001),
])
def test_flow_capacity_bounds(field, value):
    with pytest.raises(ValueError):
        MetadataFlowConfig(**{field: value})
