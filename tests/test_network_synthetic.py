"""
Tests for Synthetic Packet Test Harness.
Ensures the factory methods produce safe, parser-compatible dictionary structures.
"""

import pytest

from network.constants import (
    PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP, PROTOCOL_OTHER
)
from network.synthetic import (
    create_tcp_packet,
    create_udp_packet,
    create_icmp_packet,
    create_other_packet,
    create_malformed_packet,
    create_forbidden_payload_packet,
    create_packet_sequence
)
from network.parser import parse_packet


def test_create_tcp_packet():
    """Verify tcp packet factory produces a valid dictionary."""
    packet = create_tcp_packet()
    assert isinstance(packet, dict)
    assert packet["protocol"] == PROTOCOL_TCP
    assert "source_port" in packet
    assert "tcp_flags" in packet
    assert "payload" not in packet
    
    # Verify it parses cleanly
    meta = parse_packet(packet)
    assert meta.protocol == PROTOCOL_TCP


def test_create_udp_packet():
    """Verify udp packet factory produces a valid dictionary."""
    packet = create_udp_packet()
    assert packet["protocol"] == PROTOCOL_UDP
    assert "source_port" in packet
    assert "tcp_flags" not in packet
    
    meta = parse_packet(packet)
    assert meta.protocol == PROTOCOL_UDP


def test_create_icmp_packet():
    """Verify icmp packet factory produces a valid dictionary."""
    packet = create_icmp_packet()
    assert packet["protocol"] == PROTOCOL_ICMP
    assert "source_port" not in packet  # No ports in base icmp
    
    meta = parse_packet(packet)
    assert meta.protocol == PROTOCOL_ICMP
    assert meta.source_port is None


def test_create_other_packet():
    """Verify other packet factory produces a valid dictionary."""
    packet = create_other_packet()
    assert packet["protocol"] == PROTOCOL_OTHER
    
    meta = parse_packet(packet)
    assert meta.protocol == PROTOCOL_OTHER


def test_synthetic_customization():
    """Verify synthetic factories accept overrides."""
    packet = create_tcp_packet(
        source_ip="10.1.2.3",
        destination_port=8080,
        tcp_flags="SYN",
        packet_size=999
    )
    assert packet["source_ip"] == "10.1.2.3"
    assert packet["destination_port"] == 8080
    assert packet["tcp_flags"] == "SYN"
    assert packet["packet_size"] == 999
    
    meta = parse_packet(packet)
    assert meta.source_ip == "10.1.2.3"
    assert meta.destination_port == 8080


def test_malformed_packet_factory():
    """Verify malformed packet factory actually fails parsing."""
    packet = create_malformed_packet()
    with pytest.raises(ValueError):
        parse_packet(packet)


def test_forbidden_payload_packet_factory():
    """Verify forbidden payload factory is correctly rejected by the parser."""
    packet = create_forbidden_payload_packet()
    
    # The packet itself should have the bad fields
    assert "payload" in packet
    assert "credentials" in packet
    
    # But the parser MUST reject it
    with pytest.raises(ValueError, match="CRITICAL PRIVACY VIOLATION"):
        parse_packet(packet)


def test_packet_sequence_generation():
    """Verify sequence generator handles timing, counts, and mixed protocols."""
    seq = create_packet_sequence(
        flow_count=2,
        packets_per_flow=3,
        interval_seconds=1.0,
        mixed_protocols=True
    )
    
    assert len(seq) == 6
    
    # Assert chronology
    for i in range(1, len(seq)):
        assert seq[i]["timestamp"] >= seq[i-1]["timestamp"]
        
    # Parse them all to ensure they are valid
    parsed_sequence = [parse_packet(p) for p in seq]
    
    # Check that FlowKeys properly group them
    flow_keys = {p.get_flow_key() for p in parsed_sequence}
    assert len(flow_keys) == 2  # 2 flows requested
    
    # We requested mixed protocols
    protocols = {key.protocol for key in flow_keys}
    assert len(protocols) == 2  # TCP and UDP
