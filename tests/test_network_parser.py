"""
Tests for Packet Metadata Parser.
Ensures safe packet parsing, protocol validation, tcp flag extraction, 
direction classification, and rigorous payload rejection.
"""

import pytest
import time

from network.constants import (
    PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP, PROTOCOL_OTHER
)
from network.parser import (
    parse_packet,
    validate_packet_structure,
    extract_tcp_flags,
    determine_direction,
    detect_protocol
)
from network.metadata import PacketMetadata


def test_validate_packet_structure_safe():
    """Verify safe dictionary passes structure validation."""
    safe_packet = {"source_ip": "1.1.1.1", "packet_size": 100}
    validate_packet_structure(safe_packet)


def test_validate_packet_structure_forbidden():
    """Verify dictionary with forbidden payload fields fails."""
    forbidden_keys = ["payload", "RAW_PAYLOAD", "body", "cookie", "data"]
    for key in forbidden_keys:
        bad_packet = {"source_ip": "1.1.1.1", key: "evil_data"}
        with pytest.raises(ValueError, match="CRITICAL PRIVACY VIOLATION"):
            validate_packet_structure(bad_packet)


def test_extract_tcp_flags():
    """Verify robust TCP flag normalization."""
    # List format
    assert extract_tcp_flags({"tcp_flags": ["SYN", "ACK"]}) == "SYN,ACK"
    # String format
    assert extract_tcp_flags({"tcp_flags": "SYN, ACK "}) == "SYN,ACK"
    # Case insensitive
    assert extract_tcp_flags({"tcp_flags": ["syn", "fin"]}) == "SYN,FIN"
    # Filter unknown flags
    assert extract_tcp_flags({"tcp_flags": ["SYN", "UNKNOWN", "ACK"]}) == "SYN,ACK"
    # Empty
    assert extract_tcp_flags({}) == ""


def test_determine_direction():
    """Verify traffic direction based on local addresses."""
    locals = {"192.168.1.10", "192.168.1.11"}
    
    assert determine_direction("192.168.1.10", "192.168.1.11", locals) == "internal"
    assert determine_direction("192.168.1.10", "8.8.8.8", locals) == "outbound"
    assert determine_direction("8.8.8.8", "192.168.1.10", locals) == "inbound"
    assert determine_direction("8.8.8.8", "1.1.1.1", locals) == "external"
    assert determine_direction("", "8.8.8.8", locals) == "unknown"


def test_detect_protocol():
    """Verify protocol detection string casting and defaulting."""
    assert detect_protocol({"protocol": "tcp"}) == PROTOCOL_TCP
    assert detect_protocol({"protocol": "UDP"}) == PROTOCOL_UDP
    assert detect_protocol({"protocol": "ICMP"}) == PROTOCOL_ICMP
    assert detect_protocol({"protocol": "UNKNOWN"}) == PROTOCOL_OTHER
    assert detect_protocol({}) == PROTOCOL_OTHER


def test_parse_valid_tcp_packet():
    """Verify full parsing of a valid TCP packet representation."""
    packet_dict = {
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "tcp",
        "packet_size": 1500,
        "ttl": 64,
        "tcp_flags": "SYN",
        "interface_name": "eth0"
    }
    
    locals = {"192.168.1.10"}
    meta = parse_packet(packet_dict, local_addresses=locals)
    
    assert isinstance(meta, PacketMetadata)
    assert meta.source_ip == "192.168.1.10"
    assert meta.protocol == PROTOCOL_TCP
    assert meta.direction == "outbound"
    assert meta.tcp_flags == "SYN"
    assert meta.source_port == 12345
    assert meta.packet_size == 1500


def test_parse_valid_icmp_packet():
    """Verify parsing of ICMP which should lack ports."""
    packet_dict = {
        "source_ip": "8.8.8.8",
        "destination_ip": "192.168.1.10",
        "protocol": "icmp",
        "packet_size": 64
    }
    
    meta = parse_packet(packet_dict)
    assert meta.protocol == PROTOCOL_ICMP
    assert meta.source_port is None
    assert meta.destination_port is None
    assert meta.direction == "external"  # No locals provided
    assert meta.tcp_flags == ""


def test_parse_missing_required_fields():
    """Verify failure on missing IPs."""
    packet_dict = {"source_ip": "1.1.1.1"} # Missing dest
    with pytest.raises(ValueError, match="Missing required IP"):
        parse_packet(packet_dict)


def test_parse_invalid_ports():
    """Verify failure on bad ports for TCP/UDP."""
    packet_dict = {
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "protocol": "tcp",
        "source_port": "abc", # Invalid type
        "destination_port": 80
    }
    with pytest.raises(ValueError, match="must be integers"):
        parse_packet(packet_dict)
        
    packet_dict["source_port"] = None
    with pytest.raises(ValueError, match="Ports are required"):
        parse_packet(packet_dict)


def test_parse_invalid_size():
    """Verify failure on negative packet sizes."""
    packet_dict = {
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "protocol": "icmp",
        "packet_size": -10
    }
    with pytest.raises(ValueError, match="Must be a non-negative integer"):
        parse_packet(packet_dict)


def test_parse_invalid_ttl():
    """Verify failure on out of bound TTL."""
    packet_dict = {
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "protocol": "icmp",
        "ttl": 300
    }
    with pytest.raises(ValueError, match="between 0 and 255"):
        parse_packet(packet_dict)


def test_parse_invalid_timestamp():
    """Verify failure on invalid timestamps."""
    packet_dict = {
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "protocol": "icmp",
        "timestamp": "not_a_time"
    }
    with pytest.raises(ValueError, match="Invalid timestamp"):
        parse_packet(packet_dict)


def test_payload_absence_guarantee():
    """Ultimate guarantee test: passing an otherwise perfect packet with a payload field must fail."""
    packet_dict = {
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "tcp",
        "payload": b"secret_data"
    }
    
    with pytest.raises(ValueError) as exc:
        parse_packet(packet_dict)
        
    # Crucially, ensure the payload itself is NOT logged in the exception message
    assert "secret_data" not in str(exc.value)
