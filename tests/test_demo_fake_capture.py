from dataclasses import asdict

from ai.inference import InferenceEngine
from ai.model_registry import ModelRegistry
from alerts.policy import AlertPolicy, DecisionInput, ThresholdConfig
from network.capture_config import CaptureConfig
from network.capture_flow_processor import CaptureFlowProcessor
from network.capture_service import CaptureService
from network.fake_source import FakePacketSource, metadata_for_config
from network.flow_aggregation_service import FlowAggregationService
from network.flow_config import MetadataFlowConfig
from network.flow_feature_service import FlowFeatureService
from network.interfaces import InterfaceDiscoveryService


class _Interfaces:
    def resolve(self, key):
        assert key == "demo-interface"
        return "fake0"


def _capture_and_process():
    capture_config = CaptureConfig(
        enabled=True,
        source="fake",
        fake_source_permitted=True,
        read_timeout_seconds=0.01,
        stop_join_timeout_seconds=1.0,
    )
    app_config = {
        "ENVIRONMENT": "development",
        "DEMO_MODE": True,
    }
    capture = CaptureService(
        capture_config,
        lambda cfg, native, key: FakePacketSource(
            metadata_for_config(app_config, cfg, key)
        ),
        _Interfaces(),
    )
    aggregation = FlowAggregationService(MetadataFlowConfig())
    processor = CaptureFlowProcessor(
        capture, aggregation, FlowFeatureService(), MetadataFlowConfig()
    )
    capture.start_capture("demo-interface")
    capture.stop_capture()
    completed = processor.process()
    return completed, processor, capture


def test_fixture_is_deterministic_and_strictly_demo_gated():
    capture_config = CaptureConfig(
        enabled=True, source="fake", fake_source_permitted=True
    )
    allowed = metadata_for_config(
        {"ENVIRONMENT": "development", "DEMO_MODE": True},
        capture_config,
        "demo-interface",
    )
    blocked_production = metadata_for_config(
        {"ENVIRONMENT": "production", "DEMO_MODE": True},
        capture_config,
        "demo-interface",
    )
    blocked_without_demo = metadata_for_config(
        {"ENVIRONMENT": "development", "DEMO_MODE": False},
        capture_config,
        "demo-interface",
    )

    assert len(allowed) == 20
    assert allowed == metadata_for_config(
        {"ENVIRONMENT": "development", "DEMO_MODE": True},
        capture_config,
        "demo-interface",
    )
    assert blocked_production == ()
    assert blocked_without_demo == ()
    assert all(item.packet_length == 64 for item in allowed)
    assert all(item.direction == "outbound" for item in allowed)


def test_demo_capture_uses_normal_aggregation_and_feature_pipeline():
    completed, processor, capture = _capture_and_process()

    assert capture.final_summary().packet_count == 20
    assert len(completed) == 1
    flow = completed[0]
    assert flow.packet_count == 20
    assert flow.total_bytes == 1280
    assert flow.duration_seconds == 0.19
    assert processor.status_snapshot().feature_vectors_created == 1
    assert FlowFeatureService().extract(flow).vector.protocol_enc == 1
    assert FlowFeatureService().extract(flow).vector.direction_enc == 2


def test_demo_flow_uses_active_model_and_normal_policy():
    completed, _, _ = _capture_and_process()
    flow = completed[0]
    features = FlowFeatureService().extract(flow).vector
    prediction = InferenceEngine.from_active_registry(
        "models/registry.json"
    ).predict_one(asdict(features))
    recommendation = AlertPolicy(ThresholdConfig(min_confidence=0.30)).evaluate(DecisionInput(
        predicted_canonical_label=prediction["predicted_canonical_label"],
        confidence_score=prediction["confidence_score"],
        risk_score=prediction["risk_score"],
        model_version=prediction["model_version"],
        schema_version=flow.schema_version,
        source_category="live_metadata_flow",
        occurrence_count=1,
        observation_window_seconds=1,
        current_monitoring_state="metadata_flow_evaluation",
        pseudonymous_source_key=flow.flow_id,
    ))

    assert prediction["model_version"] == "demo-1.0.0"
    assert prediction["predicted_canonical_label"] == "port_scan"
    assert recommendation.should_create_alert is True
    assert recommendation.proposed_type.value == "suspected_port_scan"


def test_demo_registry_keeps_real_data_model_inactive():
    registry = ModelRegistry("models/registry.json")

    assert registry.get_active_model_version() == "demo-1.0.0"
    assert "cicids2017-rf-1.0.0" not in registry.list_models()
