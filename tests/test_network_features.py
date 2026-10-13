"""
Tests for Feature Extraction Layer.
Ensures purely numerical, payload-free features are generated correctly 
without external ML dependencies.
"""

import pytest

from network.constants import PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP, PROTOCOL_OTHER
from network.metadata import PacketMetadata, FlowMetadata
from network.parser import parse_packet
from network.synthetic import create_tcp_packet, create_icmp_packet
from network.flow import FlowAggregator
from network.features import (
    normalize_protocol,
    normalize_direction,
    extract_packet_features,
    extract_flow_features,
    build_feature_vector,
    PACKET_FEATURE_ORDER,
    FLOW_FEATURE_ORDER
)


def _generate_parsed_packet(factory_func, **kwargs) -> PacketMetadata:
    """Helper to generate and parse a safe packet."""
    raw_dict = factory_func(**kwargs)
    return parse_packet(raw_dict, local_addresses={"192.168.1.10"})


def test_normalize_protocol():
    """Verify categorical encoding of protocols."""
    assert normalize_protocol(PROTOCOL_TCP) == 1
    assert normalize_protocol(PROTOCOL_UDP) == 2
    assert normalize_protocol(PROTOCOL_ICMP) == 3
    assert normalize_protocol(PROTOCOL_OTHER) == 0
    assert normalize_protocol("unknown") == 0
    assert normalize_protocol(None) == 0


def test_normalize_direction():
    """Verify categorical encoding of direction."""
    assert normalize_direction("internal") == 1
    assert normalize_direction("outbound") == 2
    assert normalize_direction("inbound") == 3
    assert normalize_direction("external") == 4
    assert normalize_direction("unknown") == 0
    assert normalize_direction("invalid") == 0
    assert normalize_direction(None) == 0


def test_extract_packet_features():
    """Verify packet metadata is converted to numerical dictionary."""
    packet = _generate_parsed_packet(
        create_tcp_packet, 
        source_ip="192.168.1.10", 
        destination_ip="8.8.8.8",
        source_port=12345,
        destination_port=80,
        packet_size=500,
        ttl=128,
        tcp_flags="SYN,ACK"
    )
    
    features = extract_packet_features(packet)
    
    assert isinstance(features, dict)
    assert features["packet_size"] == 500
    assert features["protocol_enc"] == 1  # TCP
    assert features["source_port"] == 12345
    assert features["destination_port"] == 80
    assert features["ttl"] == 128
    assert features["direction_enc"] == 2  # outbound
    
    # Flags
    assert features["flag_syn"] == 1
    assert features["flag_ack"] == 1
    assert features["flag_fin"] == 0
    assert features["flag_rst"] == 0
    assert features["flag_psh"] == 0
    assert features["flag_urg"] == 0


def test_extract_packet_features_icmp():
    """Verify ICMP packet features (no ports)."""
    packet = _generate_parsed_packet(create_icmp_packet)
    features = extract_packet_features(packet)
    
    assert features["protocol_enc"] == 3  # ICMP
    assert features["source_port"] == -1
    assert features["destination_port"] == -1


def test_extract_flow_features():
    """Verify flow metadata is converted to numerical dictionary."""
    aggregator = FlowAggregator()
    
    p1 = _generate_parsed_packet(create_tcp_packet, source_ip="192.168.1.10", packet_size=100)
    p2 = _generate_parsed_packet(create_tcp_packet, source_ip="192.168.1.10", packet_size=300)
    
    aggregator.add_packet(p1)
    flow = aggregator.add_packet(p2)
    
    features = extract_flow_features(flow)
    
    assert isinstance(features, dict)
    assert features["packet_count"] == 2
    assert features["byte_count"] == 400
    assert features["min_packet_size"] == 100
    assert features["max_packet_size"] == 300
    assert features["avg_packet_size"] == 200.0
    assert features["protocol_enc"] == 1
    assert features["direction_enc"] == 2  # outbound


def test_build_feature_vector():
    """Verify deterministic ordering of feature vectors."""
    features = {
        "packet_size": 1500,
        "protocol_enc": 1,
        "source_port": 80,
        "destination_port": 12345,
        "ttl": 64,
        "direction_enc": 3,
        "flag_syn": 1,
        "flag_ack": 0,
        "flag_fin": 0,
        "flag_rst": 0,
        "flag_psh": 1,
        "flag_urg": 0
    }
    
    vector = build_feature_vector(features, PACKET_FEATURE_ORDER)
    
    assert isinstance(vector, list)
    assert len(vector) == len(PACKET_FEATURE_ORDER)
    
    # Verify the order matches the constant
    assert vector[0] == 1500  # packet_size
    assert vector[1] == 1     # protocol_enc
    assert vector[2] == 80    # source_port
    assert vector[3] == 12345 # destination_port
    
    # Missing feature should default to 0.0 safely
    partial_features = {"packet_size": 50}
    partial_vector = build_feature_vector(partial_features, PACKET_FEATURE_ORDER)
    assert partial_vector[0] == 50
    assert partial_vector[1] == 0.0


def test_invalid_input_rejection():
    """Verify invalid inputs raise ValueErrors."""
    with pytest.raises(ValueError):
        extract_packet_features("not_a_packet")
        
    with pytest.raises(ValueError):
        extract_flow_features({"not": "a_flow"})
        
    with pytest.raises(ValueError):
        build_feature_vector("not_dict", PACKET_FEATURE_ORDER)
        
    with pytest.raises(ValueError):
        build_feature_vector({}, "not_list")


def test_no_payloads_in_output():
    """Verify the output dictionaries/lists contain strictly primitive numbers."""
    packet = _generate_parsed_packet(create_tcp_packet)
    features = extract_packet_features(packet)
    vector = build_feature_vector(features, PACKET_FEATURE_ORDER)
    
    # Dictionary assertions
    for k, v in features.items():
        assert isinstance(v, (int, float))
        assert "payload" not in k.lower()
        
    # Vector assertions
    for v in vector:
        assert isinstance(v, (int, float))
