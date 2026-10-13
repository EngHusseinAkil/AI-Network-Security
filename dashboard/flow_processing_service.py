"""Safe dashboard/status adapter for explicit metadata-flow processing."""


def _iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def _flow_summary(flow):
    if flow is None:
        return None
    return {
        "flow_id": flow.flow_id,
        "interface_key": flow.interface_key,
        "protocol": flow.protocol,
        "direction": flow.direction,
        "first_seen": _iso(flow.first_seen),
        "last_seen": _iso(flow.last_seen),
        "duration_seconds": flow.duration_seconds,
        "packet_count": flow.packet_count,
        "total_bytes": flow.total_bytes,
        "minimum_packet_length": flow.minimum_packet_length,
        "maximum_packet_length": flow.maximum_packet_length,
        "mean_packet_length": flow.mean_packet_length,
        "completed_reason": flow.completed_reason.value,
        "source_mode": flow.source_mode,
        "capture_session_id": flow.capture_session_id,
        "schema_version": flow.schema_version,
        "source_ip": (flow.endpoint_metadata.source_ip
                       if flow.endpoint_metadata else None),
        "destination_ip": (flow.endpoint_metadata.destination_ip
                            if flow.endpoint_metadata else None),
        "source_mac": (flow.endpoint_metadata.source_mac
                        if flow.endpoint_metadata else None),
        "destination_mac": (flow.endpoint_metadata.destination_mac
                        if flow.endpoint_metadata else None),
        "monitored_device_ip": flow.monitored_device_ip,
    }


class DashboardFlowProcessingService:
    def __init__(self, processor, aggregation):
        self._processor = processor
        self._aggregation = aggregation

    def process(self):
        return self._processor.process()

    def get_completed_flow(self, flow_id):
        """Return the retained completed flow tied to an evaluation flow_id."""
        if not flow_id:
            return None
        for flow in self._aggregation.completed_snapshot():
            if flow.flow_id == flow_id:
                return _flow_summary(flow)
        return None

    def status(self):
        processing = self._processor.status_snapshot()
        aggregation = self._aggregation.status_snapshot()
        return {
            "metadata_records_drained": processing.metadata_records_drained,
            "metadata_records_processed": processing.metadata_records_processed,
            "metadata_processing_failures": processing.metadata_processing_failures,
            "active_flow_count": aggregation.active_flow_count,
            "completed_flow_count": aggregation.completed_flow_count,
            "completed_flow_eviction_count": aggregation.completed_flow_eviction_count,
            "feature_vectors_created": processing.feature_vectors_created,
            "incompatible_flow_count": processing.incompatible_flow_count,
            "last_processing_timestamp": _iso(processing.last_processing_timestamp),
            "last_flow_processing_error_category": processing.last_safe_error_category,
            "latest_completed_flow": _flow_summary(aggregation.latest_completed_flow),
        }
