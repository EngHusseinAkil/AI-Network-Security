import os
import math
import pytest
from unittest.mock import Mock, patch

from network.metadata import FlowMetadata, FlowKey
from network.features import extract_flow_features, FLOW_FEATURE_ORDER
from ai.inference import InferenceEngine
from ai.network_integration import FlowInferenceAdapter
from utils.exceptions import ValidationError

from ai.constants import RANDOM_SEED, FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from ai.preprocessing import LABEL_TO_INDEX
from ai.training import train_random_forest
from ai.model_persistence import save_model_artifact

@pytest.fixture
def synthetic_training_data():
    X = [
        [1.0, 10.0, 100.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.1, 11.0, 110.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [1.2, 12.0, 120.0, 64.0, 64.0, 64.0, 1.0, 2.0],
        [0.1, 1000.0, 64000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.2, 2000.0, 128000.0, 64.0, 64.0, 64.0, 1.0, 3.0],
        [0.3, 3000.0, 192000.0, 64.0, 64.0, 64.0, 1.0, 3.0]
    ]
    y = [LABEL_TO_INDEX["benign"]] * 3 + [LABEL_TO_INDEX["ddos"]] * 3
    metadata = {
        "schema_type": "flow",
        "schema_version": FLOW_SCHEMA_VERSION,
        "preprocessing_version": "1.0.0",
        "ordered_feature_names": FLOW_FEATURE_ORDER,
        "feature_count": len(FLOW_FEATURE_ORDER),
        "label_encoding_map": LABEL_TO_INDEX,
        "random_seed_used": RANDOM_SEED
    }
    return {"X": X, "y": y, "metadata": metadata}

@pytest.fixture
def trained_result(synthetic_training_data):
    return train_random_forest(
        synthetic_training_data, test_ratio=0.5, allow_unstratified_fallback_for_tests=False
    )

@pytest.fixture
def model_dir(tmp_path, trained_result):
    return save_model_artifact(trained_result, None, str(tmp_path), "v1.0.0")

@pytest.fixture
def inference_engine(model_dir):
    return InferenceEngine.from_artifact(model_dir)

@pytest.fixture
def adapter(inference_engine):
    return FlowInferenceAdapter(inference_engine)

@pytest.fixture
def valid_flow():
    flow = FlowMetadata(
        FlowKey(source_ip="192.168.1.1", destination_ip="10.0.0.1", source_port=12345, destination_port=80, protocol="TCP"),
        start_time=1000.0,
        end_time=1001.0
    )
    flow.packet_count = 10
    flow.byte_count = 1000
    flow.min_packet_size = 64
    flow.max_packet_size = 128
    flow.direction = "outbound"
    return flow

def test_adapter_initialization(adapter):
    status = adapter.get_integration_status()
    assert status["status"] == "ready"
    assert status["model_info"]["model_version"] == "v1.0.0"

def test_missing_benign_class_fails():
    engine = Mock(spec=InferenceEngine)
    engine.get_model_info.return_value = {
        "schema_version": "1.0.0",
        "feature_count": len(FLOW_FEATURE_ORDER)
    }
    engine.supports_canonical_label.return_value = False
    engine.validate_runtime_compatibility.return_value = True
    with pytest.raises(ValidationError, match="canonical 'benign' class is absent"):
        FlowInferenceAdapter(engine)

def test_valid_completed_flow_predicts_successfully(adapter, valid_flow):
    res = adapter.predict_completed_flow(valid_flow)
    assert res["integration_status"] == "success"
    assert "canonical_label" in res["prediction"]
    assert "risk_score" in res["prediction"]
    import hashlib
    raw_key = str(valid_flow.flow_key)
    expected_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:16]
    assert res["flow_identifier"] == expected_hash

def test_raw_packet_input_is_rejected(adapter):
    with pytest.raises(ValidationError, match="must be a valid FlowMetadata object"):
        adapter.predict_completed_flow({"packet_bytes": "abc"})

def test_empty_flow_rejected(adapter, valid_flow):
    valid_flow.packet_count = 0
    with pytest.raises(ValidationError, match="zero or negative packet count"):
        adapter.predict_completed_flow(valid_flow)

def test_negative_bytes_rejected(adapter, valid_flow):
    valid_flow.byte_count = -100
    with pytest.raises(ValidationError, match="negative byte count"):
        adapter.predict_completed_flow(valid_flow)

def test_negative_duration_rejected(adapter, valid_flow):
    valid_flow.start_time = 2000.0
    valid_flow.end_time = 1000.0
    valid_flow.duration = -1000.0
    with pytest.raises(ValidationError, match="negative duration"):
        adapter.predict_completed_flow(valid_flow)

def test_missing_protocol_rejected(adapter, valid_flow):
    valid_flow.protocol = None
    with pytest.raises(ValidationError, match="missing a protocol definition"):
        adapter.predict_completed_flow(valid_flow)

def test_nan_infinity_rejected(adapter, valid_flow, monkeypatch):
    # Mock extract_flow_features to return a NaN to test downstream check
    def mock_extract(*args):
        feats = {f: 1.0 for f in FLOW_FEATURE_ORDER}
        feats["duration"] = math.nan
        return feats

    monkeypatch.setattr("ai.network_integration.extract_flow_features", mock_extract)
    with pytest.raises(ValidationError, match="contains NaN or Infinity"):
        adapter.predict_completed_flow(valid_flow)

def test_caller_owned_objects_not_mutated(adapter, valid_flow):
    original_pkt_count = valid_flow.packet_count
    adapter.predict_completed_flow(valid_flow)
    assert valid_flow.packet_count == original_pkt_count

def test_batch_output_order_matches(adapter, valid_flow):
    flow2 = FlowMetadata(
        FlowKey(source_ip="192.168.1.2", destination_ip="10.0.0.2", source_port=12345, destination_port=80, protocol="TCP"),
        start_time=1000.0,
        end_time=1002.0
    )
    flow2.packet_count = 20
    flow2.byte_count = 2000
    flow2.min_packet_size = 64
    flow2.max_packet_size = 128
    flow2.direction = "outbound"

    import hashlib
    raw_key1 = str(valid_flow.flow_key)
    hash1 = hashlib.sha256(raw_key1.encode('utf-8')).hexdigest()[:16]

    raw_key2 = str(flow2.flow_key)
    hash2 = hashlib.sha256(raw_key2.encode('utf-8')).hexdigest()[:16]

    results = adapter.predict_completed_flows([valid_flow, flow2])
    assert len(results) == 2
    assert results[0]["flow_identifier"] == hash1
    assert results[1]["flow_identifier"] == hash2

def test_malformed_strict_batch_fails_before_prediction(adapter, valid_flow, monkeypatch):
    flow2 = FlowMetadata(
        FlowKey(source_ip="192.168.1.2", destination_ip="10.0.0.2", source_port=12345, destination_port=80, protocol="TCP"),
        start_time=1000.0,
        end_time=1002.0
    )
    flow2.packet_count = -1 # Malformed

    # Prove prediction is never reached on engine
    mock_predict = Mock()
    monkeypatch.setattr(adapter._engine, "predict_batch", mock_predict)

    with pytest.raises(ValidationError, match="Batch prediction aborted"):
        adapter.predict_completed_flows([valid_flow, flow2])

    mock_predict.assert_not_called()

def test_prediction_result_preserves_values(adapter, valid_flow):
    res = adapter.predict_completed_flow(valid_flow)
    pred = res["prediction"]
    assert isinstance(pred["confidence_score"], float)
    assert isinstance(pred["risk_score"], float)
    assert 0.0 <= pred["risk_score"] <= 1.0

def test_no_side_effects():
    import sys
    assert "scapy.all" not in sys.modules or "ai.network_integration" in sys.modules
    assert "sqlalchemy" not in sys.modules or "ai.network_integration" in sys.modules
    assert "flask" not in sys.modules or "ai.network_integration" in sys.modules
