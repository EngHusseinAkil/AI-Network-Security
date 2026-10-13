from dataclasses import fields
from datetime import datetime, timezone

from network.features import FLOW_FEATURE_ORDER
from network.flow_feature_service import FlowFeatureService
from network.flow_models import FlowCompletionReason, MetadataFlowRecord, NetworkFeatureVector


def flow(packet_count=2, direction="inbound"):
    now = datetime.now(timezone.utc)
    return MetadataFlowRecord(
        "id", "key", "UDP", direction, now, now, 1.5, packet_count, 40,
        10, 30, 20, FlowCompletionReason.MANUAL_FLUSH, "fake", None,
    )


def test_exact_authoritative_eight_field_schema():
    assert [field.name for field in fields(NetworkFeatureVector)] == FLOW_FEATURE_ORDER
    assert FlowFeatureService.feature_order == tuple(FLOW_FEATURE_ORDER)


def test_compatible_flow_maps_exact_values():
    result = FlowFeatureService().extract(flow())
    assert result.compatible
    assert result.vector.as_ordered_tuple() == (1.5, 2, 40, 10, 30, 20, 2, 3)


def test_unknown_direction_uses_existing_schema_encoding():
    assert FlowFeatureService().extract(flow(direction="unknown")).vector.direction_enc == 0


def test_empty_flow_is_safely_incompatible():
    result = FlowFeatureService().extract(flow(packet_count=0))
    assert not result.compatible and result.vector is None
    assert result.incompatibility_reason == "empty_flow"


def test_invalid_type_is_safely_incompatible():
    result = FlowFeatureService().extract(object())
    assert result.incompatibility_reason == "invalid_flow_type"
