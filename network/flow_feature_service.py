"""Pure metadata-flow to authoritative eight-field feature conversion."""
from .features import FLOW_FEATURE_ORDER, normalize_direction, normalize_protocol
from .flow_models import (
    FeatureExtractionResult, MetadataFlowRecord, NetworkFeatureVector,
)


class FlowFeatureService:
    feature_order = tuple(FLOW_FEATURE_ORDER)

    def extract(self, flow):
        if not isinstance(flow, MetadataFlowRecord):
            return FeatureExtractionResult(False, None, "invalid_flow_type")
        if flow.packet_count == 0:
            return FeatureExtractionResult(False, None, "empty_flow")
        vector = NetworkFeatureVector(
            flow.duration_seconds,
            flow.packet_count,
            flow.total_bytes,
            flow.minimum_packet_length,
            flow.maximum_packet_length,
            flow.mean_packet_length,
            normalize_protocol(flow.protocol),
            normalize_direction(flow.direction),
        )
        return FeatureExtractionResult(True, vector, None)
