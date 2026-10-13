import pytest
import math

from network.features import PACKET_FEATURE_ORDER, FLOW_FEATURE_ORDER
from ai.constants import CANONICAL_LABELS, PACKET_SCHEMA_VERSION, FLOW_SCHEMA_VERSION
from ai.schema import (
    validate_packet_feature_dict,
    validate_flow_feature_dict,
    validate_feature_vector,
    validate_feature_order,
    validate_canonical_label,
    get_packet_schema_metadata,
    get_flow_schema_metadata
)
from utils.exceptions import ValidationError


def test_packet_schema_order_matches_network_engine():
    assert get_packet_schema_metadata()["ordered_features"] == PACKET_FEATURE_ORDER
    validate_feature_order(PACKET_FEATURE_ORDER, PACKET_FEATURE_ORDER)

def test_flow_schema_order_matches_network_engine():
    assert get_flow_schema_metadata()["ordered_features"] == FLOW_FEATURE_ORDER
    validate_feature_order(FLOW_FEATURE_ORDER, FLOW_FEATURE_ORDER)

def test_correct_packet_feature_dict_passes():
    valid_features = {
        "packet_size": 1500,
        "protocol_enc": 1,
        "source_port": -1,  # Valid runtime sentinel for missing ports
        "destination_port": 80,
        "ttl": 64,
        "direction_enc": 2,
        "flag_syn": 1,
        "flag_ack": 0,
        "flag_fin": 0,
        "flag_rst": 0,
        "flag_psh": 0,
        "flag_urg": 0
    }
    # Should not raise exception
    validate_packet_feature_dict(valid_features, strict=True)

def test_correct_flow_feature_dict_passes():
    valid_features = {
        "duration": 1.5,
        "packet_count": 10,
        "byte_count": 15000,
        "min_packet_size": 64,
        "max_packet_size": 1500,
        "avg_packet_size": 150.0,
        "protocol_enc": 1,
        "direction_enc": 2
    }
    # Should not raise exception
    validate_flow_feature_dict(valid_features, strict=True)

def test_missing_features_fail():
    invalid_features = {
        "duration": 1.5,
        "packet_count": 10,
        # Missing other flow features
    }
    with pytest.raises(ValidationError, match="Missing required features"):
        validate_flow_feature_dict(invalid_features, strict=True)

def test_extra_features_fail_strict():
    invalid_features = {
        "duration": 1.5,
        "packet_count": 10,
        "byte_count": 15000,
        "min_packet_size": 64,
        "max_packet_size": 1500,
        "avg_packet_size": 150.0,
        "protocol_enc": 1,
        "direction_enc": 2,
        "malicious_score": 0.99  # Extra feature
    }
    with pytest.raises(ValidationError, match="Unexpected extra features found"):
        validate_flow_feature_dict(invalid_features, strict=True)

    # Should pass if strict is False
    validate_flow_feature_dict(invalid_features, strict=False)

def test_invalid_numerical_values_fail():
    invalid_features = {
        "duration": "1.5",  # Invalid type (string)
        "packet_count": 10,
        "byte_count": 15000,
        "min_packet_size": 64,
        "max_packet_size": 1500,
        "avg_packet_size": 150.0,
        "protocol_enc": 1,
        "direction_enc": 2
    }
    with pytest.raises(ValidationError, match="invalid type"):
        validate_flow_feature_dict(invalid_features)

    # Boolean values should fail since they are not purely numeric (even if they subclass int in python)
    invalid_features["duration"] = 1.5
    invalid_features["packet_count"] = True
    with pytest.raises(ValidationError, match="invalid type"):
        validate_flow_feature_dict(invalid_features)

def test_nan_and_inf_values_fail():
    invalid_features = {
        "duration": math.nan,
        "packet_count": 10,
        "byte_count": 15000,
        "min_packet_size": 64,
        "max_packet_size": 1500,
        "avg_packet_size": 150.0,
        "protocol_enc": 1,
        "direction_enc": 2
    }
    with pytest.raises(ValidationError, match="NaN or infinite value"):
        validate_flow_feature_dict(invalid_features)

    invalid_features["duration"] = math.inf
    with pytest.raises(ValidationError, match="NaN or infinite value"):
        validate_flow_feature_dict(invalid_features)

def test_incorrect_vector_lengths_fail():
    valid_vector = [0.0] * len(PACKET_FEATURE_ORDER)
    validate_feature_vector(valid_vector, len(PACKET_FEATURE_ORDER))

    invalid_vector = [0.0] * (len(PACKET_FEATURE_ORDER) - 1)
    with pytest.raises(ValidationError, match="length mismatch"):
        validate_feature_vector(invalid_vector, len(PACKET_FEATURE_ORDER))

def test_schema_metadata_deterministic():
    meta1 = get_packet_schema_metadata()
    meta2 = get_packet_schema_metadata()
    assert meta1 == meta2
    assert meta1["schema_version"] == PACKET_SCHEMA_VERSION
    assert "-1" in meta1["port_semantics"]
    assert "0" in meta1["port_semantics"]
    assert meta1["source_module"] == "network.features"

def test_icmp_feature_extraction_emits_minus_one():
    from network.metadata import PacketMetadata
    from network.features import extract_packet_features

    # Simulate an ICMP packet which has no ports
    icmp_packet = PacketMetadata(
        timestamp=1000.0,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=None,
        destination_port=None,
        protocol="ICMP",
        packet_size=64,
        ttl=128
    )

    features = extract_packet_features(icmp_packet)

    # Assert network.features authoritative logic emits -1
    assert features["source_port"] == -1
    assert features["destination_port"] == -1

    # Assert ai.schema validation accepts this native output
    validate_packet_feature_dict(features, strict=True)

def test_canonical_label_validation_works():
    for label in CANONICAL_LABELS:
        validate_canonical_label(label)

    with pytest.raises(ValidationError, match="not supported"):
        validate_canonical_label("alien_attack")
