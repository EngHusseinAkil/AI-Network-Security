"""
Feature Extraction Layer.

Converts `PacketMetadata` and `FlowMetadata` into safe numerical/categorical 
features that future AI models can use. 
Strictly pure Python, independent from external machine learning libraries.
"""

from typing import Dict, List, Union

from network.metadata import PacketMetadata, FlowMetadata
from network.constants import (
    PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP,
    TCP_FLAG_SYN, TCP_FLAG_ACK, TCP_FLAG_FIN,
    TCP_FLAG_RST, TCP_FLAG_PSH, TCP_FLAG_URG
)


# Stable feature ordering constants
PACKET_FEATURE_ORDER = [
    "packet_size",
    "protocol_enc",
    "source_port",
    "destination_port",
    "ttl",
    "direction_enc",
    "flag_syn",
    "flag_ack",
    "flag_fin",
    "flag_rst",
    "flag_psh",
    "flag_urg"
]

FLOW_FEATURE_ORDER = [
    "duration",
    "packet_count",
    "byte_count",
    "min_packet_size",
    "max_packet_size",
    "avg_packet_size",
    "protocol_enc",
    "direction_enc"
]


def normalize_protocol(protocol: str) -> int:
    """
    Categorically encodes network protocols into numerical values.
    OTHER = 0, TCP = 1, UDP = 2, ICMP = 3
    """
    if not isinstance(protocol, str):
        return 0
    
    proto_map = {
        PROTOCOL_TCP: 1,
        PROTOCOL_UDP: 2,
        PROTOCOL_ICMP: 3
    }
    return proto_map.get(protocol.upper(), 0)


def normalize_direction(direction: str) -> int:
    """
    Categorically encodes traffic direction into numerical values.
    unknown = 0, internal = 1, outbound = 2, inbound = 3, external = 4
    """
    if not isinstance(direction, str):
        return 0
        
    dir_map = {
        "internal": 1,
        "outbound": 2,
        "inbound": 3,
        "external": 4
    }
    return dir_map.get(direction.lower(), 0)


def extract_packet_features(packet: PacketMetadata) -> Dict[str, Union[int, float]]:
    """
    Extracts purely numerical features from a PacketMetadata object.
    Rejects inputs that are not PacketMetadata instances.
    """
    if not isinstance(packet, PacketMetadata):
        raise ValueError("packet must be a PacketMetadata instance")
        
    features = {
        "packet_size": packet.packet_size,
        "protocol_enc": normalize_protocol(packet.protocol),
        "source_port": packet.source_port if packet.source_port is not None else -1,
        "destination_port": packet.destination_port if packet.destination_port is not None else -1,
        "ttl": packet.ttl,
        "direction_enc": normalize_direction(packet.direction)
    }
    
    # TCP flag indicators (1 or 0)
    flags = packet.tcp_flags if packet.tcp_flags else ""
    features["flag_syn"] = 1 if TCP_FLAG_SYN in flags else 0
    features["flag_ack"] = 1 if TCP_FLAG_ACK in flags else 0
    features["flag_fin"] = 1 if TCP_FLAG_FIN in flags else 0
    features["flag_rst"] = 1 if TCP_FLAG_RST in flags else 0
    features["flag_psh"] = 1 if TCP_FLAG_PSH in flags else 0
    features["flag_urg"] = 1 if TCP_FLAG_URG in flags else 0
    
    return features


def extract_flow_features(flow: FlowMetadata) -> Dict[str, Union[int, float]]:
    """
    Extracts purely numerical features from a FlowMetadata object.
    Rejects inputs that are not FlowMetadata instances.
    """
    if not isinstance(flow, FlowMetadata):
        raise ValueError("flow must be a FlowMetadata instance")
        
    features = {
        "duration": flow.duration,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "min_packet_size": flow.min_packet_size,
        "max_packet_size": flow.max_packet_size,
        "avg_packet_size": flow.avg_packet_size,
        "protocol_enc": normalize_protocol(flow.protocol),
        "direction_enc": normalize_direction(flow.direction)
    }
    
    return features


def build_feature_vector(features: Dict[str, Union[int, float]], feature_order: List[str]) -> List[Union[int, float]]:
    """
    Converts a feature dictionary into a stable ordered list (vector).
    Missing features evaluate to 0.0 to prevent pipeline crashes.
    """
    if not isinstance(features, dict):
        raise ValueError("features must be a dictionary")
    if not isinstance(feature_order, list):
        raise ValueError("feature_order must be a list of strings")
        
    vector = []
    for key in feature_order:
        vector.append(features.get(key, 0.0))
        
    return vector
