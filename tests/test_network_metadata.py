"""
Tests for Network Engine Dataclasses and Constants.
Ensures safe metadata extraction and payload exclusions.
"""

import pytest
import time

from network.constants import (
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    DEFAULT_MAX_PACKET_SAMPLE_COUNT,
    PRIVACY_PAYLOAD_EXCLUSION_RULE,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK
)
from network.metadata import (
    FlowKey,
    PacketMetadata,
    FlowMetadata,
    InterfaceMetadata
)


def test_constants_import_correctly():
    """Verify constants are defined and importable."""
    assert PROTOCOL_TCP == "TCP"
    assert PROTOCOL_UDP == "UDP"
    assert DEFAULT_MAX_PACKET_SAMPLE_COUNT == 100000
    assert "Payloads MUST NOT be stored" in PRIVACY_PAYLOAD_EXCLUSION_RULE


def test_flow_key_creation_and_validation():
    """Verify FlowKey validates ports and strings."""
    key = FlowKey("192.168.1.1", "10.0.0.1", 12345, 80, PROTOCOL_TCP)
    assert key.source_ip == "192.168.1.1"
    assert key.destination_port == 80
    
    with pytest.raises(ValueError):
        FlowKey("192.168.1.1", "10.0.0.1", 70000, 80, PROTOCOL_TCP)  # Invalid port


def test_flow_key_equality_and_hashability():
    """Verify FlowKey can be used in dictionaries/sets."""
    key1 = FlowKey("192.168.1.1", "10.0.0.1", 12345, 80, PROTOCOL_TCP)
    key2 = FlowKey("192.168.1.1", "10.0.0.1", 12345, 80, PROTOCOL_TCP)
    key3 = FlowKey("10.0.0.1", "192.168.1.1", 80, 12345, PROTOCOL_TCP)
    
    assert key1 == key2
    assert key1 != key3
    
    flow_dict = {key1: "active"}
    assert key2 in flow_dict
    assert key3 not in flow_dict


def test_packet_metadata_creation_and_payload_exclusion():
    """Verify PacketMetadata creation and payload field exclusion."""
    ts = time.time()
    packet = PacketMetadata(
        timestamp=ts,
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=53,
        protocol=PROTOCOL_UDP,
        packet_size=120,
        ttl=64
    )
    assert packet.protocol == PROTOCOL_UDP
    assert packet.packet_size == 120
    
    # Verify no payload attribute exists
    assert not hasattr(packet, "payload")
    assert not hasattr(packet, "raw_payload")

    # Manually try to add a forbidden attribute to test our dynamic guard (if implemented via setattr, but dataclasses __post_init__ tests initial injection)
    # The __post_init__ guard checks if someone inherited or injected the field during creation.
    # Since dataclasses don't easily allow undefined fields in __init__, we test the explicit lack of definition.
    with pytest.raises(TypeError):
        PacketMetadata(
            timestamp=ts,
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            source_port=54321,
            destination_port=53,
            protocol=PROTOCOL_UDP,
            packet_size=120,
            ttl=64,
            payload=b"evil_data"  # type: ignore
        )


def test_packet_metadata_to_flow_key():
    """Verify a PacketMetadata instance can generate a corresponding FlowKey."""
    packet = PacketMetadata(
        timestamp=time.time(),
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        source_port=54321,
        destination_port=53,
        protocol=PROTOCOL_UDP,
        packet_size=120,
        ttl=64
    )
    flow_key = packet.get_flow_key()
    assert isinstance(flow_key, FlowKey)
    assert flow_key.source_ip == "192.168.1.10"
    assert flow_key.destination_port == 53


def test_flow_metadata_aggregation_fields():
    """Verify FlowMetadata properly calculates duration and initializes fields."""
    key = FlowKey("192.168.1.1", "10.0.0.1", 12345, 80, PROTOCOL_TCP)
    start = time.time()
    end = start + 5.5
    
    flow_meta = FlowMetadata(
        flow_key=key,
        start_time=start,
        end_time=end,
        packet_count=100,
        byte_count=150000,
        min_packet_size=64,
        max_packet_size=1500,
        avg_packet_size=1500.0
    )
    
    assert flow_meta.duration == 5.5
    assert flow_meta.protocol == PROTOCOL_TCP
    assert flow_meta.packet_count == 100
    
    # Test invalid time range
    with pytest.raises(ValueError):
        FlowMetadata(key, start_time=end, end_time=start)


def test_dictionary_conversion():
    """Verify dataclasses convert cleanly to dictionaries."""
    key = FlowKey("1.1.1.1", "2.2.2.2", 1000, 2000, PROTOCOL_TCP)
    flow_meta = FlowMetadata(
        flow_key=key,
        start_time=100.0,
        end_time=105.0,
        packet_count=5
    )
    
    data = flow_meta.to_dict()
    assert isinstance(data, dict)
    assert data["packet_count"] == 5
    assert data["duration"] == 5.0
    assert data["source_ip"] == "1.1.1.1"  # Unrolled from FlowKey
    assert "flow_key" not in data


def test_safe_string_representation():
    """Verify string representations do not crash or leak data."""
    key = FlowKey("1.1.1.1", "2.2.2.2", 1000, 2000, PROTOCOL_TCP)
    packet = PacketMetadata(
        timestamp=100.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=1000,
        destination_port=2000,
        protocol=PROTOCOL_TCP,
        packet_size=64,
        ttl=128,
        tcp_flags=TCP_FLAG_SYN
    )
    
    key_str = str(key)
    assert "TCP 1.1.1.1:1000 -> 2.2.2.2:2000" in key_str
    
    pkt_str = str(packet)
    assert "TCP 1.1.1.1:1000" in pkt_str
    assert "Flags: SYN" in pkt_str


def test_interface_metadata():
    """Verify InterfaceMetadata dataclass."""
    iface = InterfaceMetadata(
        name="eth0",
        description="Ethernet adapter",
        is_up=True,
        mac_address="00:1A:2B:3C:4D:5E",
        ip_addresses=["192.168.1.100"]
    )
    
    assert iface.name == "eth0"
    assert iface.is_up is True
    assert "eth0" in str(iface)
    assert "UP" in str(iface)
