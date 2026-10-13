import pytest
from types import MappingProxyType
from unittest.mock import patch, MagicMock

from backend.services.inference_service import InferenceService
from backend.errors.exceptions import ServiceUnavailableError
from network.features import FLOW_FEATURE_ORDER
from utils.exceptions import ValidationError


def _valid_flow(duration=1.0, protocol_enc=1.0, direction_enc=2.0):
    return {
        "duration": duration,
        "packet_count": 2,
        "byte_count": 3,
        "min_packet_size": 4,
        "max_packet_size": 5,
        "avg_packet_size": 6.0,
        "protocol_enc": protocol_enc,
        "direction_enc": direction_enc,
    }


@patch('backend.services.inference_service.InferenceEngine')
def test_inference_service_lazy_load_success(mock_engine_class):
    mock_engine = MagicMock()
    mock_engine_class.from_active_registry.return_value = mock_engine

    service = InferenceService("dummy/registry.json")
    # At this point, engine should be None
    assert service._engine is None

    # Trigger load
    engine = service._get_engine()
    assert engine == mock_engine
    mock_engine_class.from_active_registry.assert_called_once_with("dummy/registry.json")

    # Trigger load again, should return cached
    engine2 = service._get_engine()
    assert engine2 == mock_engine
    assert mock_engine_class.from_active_registry.call_count == 1

@patch('backend.services.inference_service.InferenceEngine')
def test_inference_service_lazy_load_validation_error(mock_engine_class):
    mock_engine_class.from_active_registry.side_effect = ValidationError("Corrupt")

    service = InferenceService("dummy/registry.json")

    with pytest.raises(ServiceUnavailableError) as exc:
        service._get_engine()

    assert "model_unavailable" in str(exc.value)

@patch('backend.services.inference_service.InferenceEngine')
def test_inference_service_lazy_load_unexpected_error(mock_engine_class):
    mock_engine_class.from_active_registry.side_effect = RuntimeError("Disk failure")

    service = InferenceService("dummy/registry.json")

    with pytest.raises(ServiceUnavailableError) as exc:
        service._get_engine()

    assert "model_unavailable" in str(exc.value)

def test_inference_service_predict_flow():
    mock_engine = MagicMock()
    mock_engine.predict_one.return_value = {"prediction": "benign"}

    service = InferenceService("dummy/registry.json")
    service.inject_engine_for_testing(mock_engine)

    res = service.predict_flow({"some": 1.0})
    assert res == {"prediction": "benign"}
    mock_engine.predict_one.assert_called_once_with({"some": 1.0})

def test_inference_service_predict_flow_failure():
    mock_engine = MagicMock()
    mock_engine.predict_one.side_effect = Exception("Inference crashed")

    service = InferenceService("dummy/registry.json")
    service.inject_engine_for_testing(mock_engine)

    with pytest.raises(ServiceUnavailableError) as exc:
        service.predict_flow({"some": 1.0})

    assert "inference_failed" in str(exc.value)

def test_inference_service_predict_flows():
    mock_engine = MagicMock()
    mock_engine.predict_batch.return_value = [
        {"model_version": "v1", "predicted_canonical_label": "benign"},
        {"model_version": "v1", "predicted_canonical_label": "malicious"}
    ]

    service = InferenceService("dummy/registry.json")
    service.inject_engine_for_testing(mock_engine)

    first_flow = dict(reversed(list(_valid_flow(duration=1.0).items())))
    second_flow = _valid_flow(duration=2.0)
    res = service.predict_flows([first_flow, second_flow])
    assert res["count"] == 2
    assert res["model_version"] == "v1"
    assert len(res["predictions"]) == 2
    assert res["predictions"][0]["predicted_canonical_label"] == "benign"
    assert res["predictions"][1]["predicted_canonical_label"] == "malicious"

    normalized_rows = mock_engine.predict_batch.call_args.args[0]
    assert all(type(row) is dict for row in normalized_rows)
    assert all(list(row) == FLOW_FEATURE_ORDER for row in normalized_rows)
    assert [row["duration"] for row in normalized_rows] == [1.0, 2.0]


def test_inference_service_does_not_pass_mapping_wrapper_to_engine():
    mock_engine = MagicMock()
    service = InferenceService("dummy/registry.json")
    service.inject_engine_for_testing(mock_engine)

    with pytest.raises(ServiceUnavailableError, match="inference_failed"):
        service.predict_flows([MappingProxyType(_valid_flow())])

    mock_engine.predict_batch.assert_not_called()

def test_inference_service_predict_flows_failure():
    mock_engine = MagicMock()
    mock_engine.predict_batch.side_effect = Exception("Batch Inference crashed")

    service = InferenceService("dummy/registry.json")
    service.inject_engine_for_testing(mock_engine)

    with pytest.raises(ServiceUnavailableError) as exc:
        service.predict_flows([_valid_flow()])

    assert "inference_failed" in str(exc.value)
