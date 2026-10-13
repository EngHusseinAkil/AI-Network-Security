from datetime import datetime, timezone
from types import SimpleNamespace

from network.capture_flow_processor import CaptureFlowProcessor
from network.capture_models import CapturedPacketMetadata
from network.constants import CaptureState
from network.flow_aggregation_service import FlowAggregationService
from network.flow_config import MetadataFlowConfig
from network.flow_feature_service import FlowFeatureService


class Capture:
    def __init__(self, records, state=CaptureState.RUNNING):
        self.records = list(records)
        self.state = state
        self.limits = []
    def drain_metadata(self, limit):
        self.limits.append(limit)
        values, self.records = self.records[:limit], self.records[limit:]
        return tuple(values)
    def status_snapshot(self):
        return SimpleNamespace(source="fake", session_id="session", state=self.state)


def packet():
    return CapturedPacketMetadata(datetime.now(timezone.utc), 10, "TCP", "key")


def build(capture, **config):
    cfg = MetadataFlowConfig(**config)
    aggregation = FlowAggregationService(cfg)
    return CaptureFlowProcessor(capture, aggregation, FlowFeatureService(), cfg), aggregation


def test_processor_drains_server_bounded_batch():
    capture = Capture([packet(), packet(), packet()])
    processor, _ = build(capture, max_processing_batch=2)
    processor.process()
    status = processor.status_snapshot()
    assert capture.limits == [2]
    assert status.metadata_records_drained == status.metadata_records_processed == 2
    assert len(capture.records) == 1


def test_processor_uses_public_drain_boundary_only():
    capture = Capture([packet()])
    processor, _ = build(capture)
    processor.process()
    assert not hasattr(capture, "_metadata_queue")


def test_processor_is_explicit_and_has_no_worker():
    capture = Capture([packet()])
    processor, _ = build(capture)
    assert processor.status_snapshot().metadata_records_drained == 0
    assert not hasattr(processor, "_worker")


def test_stopped_capture_flushes_session_flow_and_creates_feature():
    capture = Capture([packet()], CaptureState.STOPPED)
    processor, aggregation = build(capture)
    completed = processor.process()
    assert len(completed) == 1
    assert processor.status_snapshot().feature_vectors_created == 1
    assert aggregation.status_snapshot().active_flow_count == 0


def test_failure_counted_without_reinsertion():
    class BrokenAggregation:
        def accept(self, *args, **kwargs):
            raise ValueError
        def flush(self, *args, **kwargs):
            return ()
    capture = Capture([packet()])
    cfg = MetadataFlowConfig()
    processor = CaptureFlowProcessor(capture, BrokenAggregation(), FlowFeatureService(), cfg)
    processor.process()
    status = processor.status_snapshot()
    assert status.metadata_processing_failures == 1
    assert status.last_safe_error_category == "metadata_processing_failed"
    assert capture.records == []
