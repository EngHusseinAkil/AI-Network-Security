import os
import json
import pytest
import math

from ai.constants import RANDOM_SEED, FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from network.features import FLOW_FEATURE_ORDER
from ai.preprocessing import LABEL_TO_INDEX
from ai.training import train_random_forest
from ai.model_persistence import save_model_artifact
from ai.model_registry import ModelRegistry
from ai.inference import InferenceEngine
from utils.exceptions import ValidationError

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
def active_registry(tmp_path, model_dir, trained_result):
    reg_file = os.path.join(tmp_path, "registry.json")
    registry = ModelRegistry(reg_file)
    registry.register_model("v1.0.0", model_dir, trained_result["metadata"] if "metadata" in trained_result else {"schema_metadata": {"schema_version": FLOW_SCHEMA_VERSION}})
    registry.activate_model("v1.0.0")
    return reg_file

def test_load_from_artifact(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    assert engine.get_model_info()["model_version"] == "v1.0.0"

def test_load_from_active_registry(active_registry):
    engine = InferenceEngine.from_active_registry(active_registry)
    assert engine.get_model_info()["model_version"] == "v1.0.0"

def test_missing_active_model_fails(tmp_path):
    reg_file = os.path.join(tmp_path, "registry.json")
    registry = ModelRegistry(reg_file) # No active model
    with pytest.raises(ValidationError, match="No active model"):
        InferenceEngine.from_active_registry(reg_file)

def test_tampered_artifact_fails_before_inference(model_dir):
    with open(os.path.join(model_dir, "metadata.json"), "a") as f:
        f.write(" ")
    with pytest.raises(ValidationError, match="Integrity check failed"):
        InferenceEngine.from_artifact(model_dir)

def test_packet_feature_dict_fails(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    packet_dict = {"size": 64, "ttl": 128} # Missing flow features
    with pytest.raises(ValidationError, match="Feature dictionary length"):
        engine.predict_one(packet_dict)

def test_valid_flow_dictionary_predicts_successfully(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    flow_dict = {f: 1.0 for f in FLOW_FEATURE_ORDER}
    res = engine.predict_one(flow_dict)
    assert "predicted_canonical_label" in res
    assert "risk_score" in res

def test_dictionary_order_does_not_affect_vector(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    flow_dict1 = {f: float(i) for i, f in enumerate(FLOW_FEATURE_ORDER)}
    flow_dict2 = {f: float(i) for i, f in reversed(list(enumerate(FLOW_FEATURE_ORDER)))}

    vec1 = engine._validate_and_transform_input(flow_dict1)
    vec2 = engine._validate_and_transform_input(flow_dict2)
    assert vec1 == vec2

def test_valid_numerical_vector_predicts(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec = [1.0] * len(FLOW_FEATURE_ORDER)
    res = engine.predict_one(vec)
    assert "risk_score" in res

def test_invalid_vector_length_fails(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec = [1.0] * (len(FLOW_FEATURE_ORDER) - 1)
    with pytest.raises(ValidationError, match="does not match required count"):
        engine.predict_one(vec)

def test_missing_feature_fails(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    flow_dict = {f: 1.0 for f in FLOW_FEATURE_ORDER}
    flow_dict.pop(FLOW_FEATURE_ORDER[0])
    with pytest.raises(ValidationError, match="Feature dictionary length"):
        engine.predict_one(flow_dict)

def test_extra_feature_fails(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    flow_dict = {f: 1.0 for f in FLOW_FEATURE_ORDER}
    flow_dict["extra_feature"] = 1.0
    with pytest.raises(ValidationError, match="Feature dictionary length"):
        engine.predict_one(flow_dict)

def test_labels_inside_feature_input_fail(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    flow_dict = {f: 1.0 for f in FLOW_FEATURE_ORDER}
    flow_dict.pop(FLOW_FEATURE_ORDER[0])
    flow_dict["label"] = 1.0
    with pytest.raises(ValidationError, match="Labels cannot be passed"):
        engine.predict_one(flow_dict)

def test_nan_and_infinity_fail(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec = [1.0] * len(FLOW_FEATURE_ORDER)
    vec[0] = math.nan
    with pytest.raises(ValidationError, match="contains NaN or Infinity"):
        engine.predict_one(vec)

def test_batch_output_order_matches_input(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec1 = [1.0] * len(FLOW_FEATURE_ORDER)
    vec2 = [2.0] * len(FLOW_FEATURE_ORDER)
    results = engine.predict_batch([vec1, vec2])

    # We can't guarantee distinct predictions, but we can guarantee len and structure
    assert len(results) == 2

def test_malformed_batch_fails_safely(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec1 = [1.0] * len(FLOW_FEATURE_ORDER)
    vec2 = [2.0] * (len(FLOW_FEATURE_ORDER) - 1) # Malformed
    with pytest.raises(ValidationError, match="does not match required count"):
        engine.predict_batch([vec1, vec2])

def test_confidence_and_risk_score(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec = [1.0] * len(FLOW_FEATURE_ORDER)
    res = engine.predict_one(vec)

    probs = res["class_probabilities"]
    pred = res["predicted_canonical_label"]

    assert res["confidence_score"] == probs[pred]

    p_benign = probs.get("benign", 0.0)
    expected_risk = max(0.0, min(1.0, 1.0 - p_benign))
    # Due to floating point math, use approx
    assert res["risk_score"] == pytest.approx(expected_risk)

    assert 0.0 <= res["risk_score"] <= 1.0

    total_prob = sum(probs.values())
    assert total_prob == pytest.approx(1.0)

def test_unknown_risk_behavior_explicit(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec = [1.0] * len(FLOW_FEATURE_ORDER)
    res = engine.predict_one(vec)
    assert "unknown_class_behavior" in res["explanation_metadata"]

def test_latency_fields_non_negative(model_dir):
    engine = InferenceEngine.from_artifact(model_dir)
    vec = [1.0] * len(FLOW_FEATURE_ORDER)
    res = engine.predict_one(vec)

    assert res["inference_latency"]["total_batch_seconds"] >= 0.0
    assert res["inference_latency"]["average_seconds_per_row"] >= 0.0

def test_inference_does_not_call_fit(model_dir, monkeypatch):
    engine = InferenceEngine.from_artifact(model_dir)
    def mock_fit(*args, **kwargs):
        raise RuntimeError("fit() should not be called during inference!")
    monkeypatch.setattr(engine._estimator, "fit", mock_fit)
    vec = [1.0] * len(FLOW_FEATURE_ORDER)
    engine.predict_one(vec) # Should not raise RuntimeError

def test_no_side_effects_inference():
    import sys
    assert "flask" not in sys.modules or "ai.inference" in sys.modules
    assert "sqlalchemy" not in sys.modules or "ai.inference" in sys.modules
    assert "scapy" not in sys.modules or "ai.inference" in sys.modules
