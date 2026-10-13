"""
Synthetic Packet Test Harness.

Provides safe, reusable synthetic packet factories for testing the network 
engine without requiring live network access, Scapy, PyShark, Npcap, 
or Administrator privileges.
"""

import time
from typing import Dict, Any, List, Optional

from network.constants import (
    PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP, PROTOCOL_OTHER,
    TCP_FLAG_SYN, TCP_FLAG_ACK, TCP_FLAG_FIN
)


def _base_packet(protocol: str, **kwargs) -> Dict[str, Any]:
    """Base factory method to create a default safe synthetic packet."""
    packet = {
        "timestamp": kwargs.get("timestamp", time.time()),
        "source_ip": kwargs.get("source_ip", "192.168.1.100"),
        "destination_ip": kwargs.get("destination_ip", "203.0.113.50"),
        "protocol": protocol,
        "packet_size": kwargs.get("packet_size", 64),
        "ttl": kwargs.get("ttl", 64),
        "interface_name": kwargs.get("interface_name", "eth0")
    }
    
    if protocol in [PROTOCOL_TCP, PROTOCOL_UDP]:
        packet["source_port"] = kwargs.get("source_port", 50000)
        packet["destination_port"] = kwargs.get("destination_port", 443)
        
    if protocol == PROTOCOL_TCP:
        packet["tcp_flags"] = kwargs.get("tcp_flags", TCP_FLAG_ACK)
        
    return packet


def create_tcp_packet(**kwargs) -> Dict[str, Any]:
    """Creates a synthetic TCP packet dictionary."""
    return _base_packet(PROTOCOL_TCP, **kwargs)


def create_udp_packet(**kwargs) -> Dict[str, Any]:
    """Creates a synthetic UDP packet dictionary."""
    return _base_packet(PROTOCOL_UDP, **kwargs)


def create_icmp_packet(**kwargs) -> Dict[str, Any]:
    """Creates a synthetic ICMP packet dictionary."""
    return _base_packet(PROTOCOL_ICMP, **kwargs)


def create_other_packet(**kwargs) -> Dict[str, Any]:
    """Creates a synthetic packet of an OTHER (unknown) protocol."""
    return _base_packet(PROTOCOL_OTHER, **kwargs)


def create_malformed_packet(**kwargs) -> Dict[str, Any]:
    """
    Creates a malformed packet dictionary missing required fields or having invalid types.
    Can be configured via kwargs (e.g. source_ip=None, packet_size=-10).
    """
    packet = _base_packet(PROTOCOL_TCP, **kwargs)
    
    # Intentionally break it if the caller hasn't already broken it
    if "source_ip" not in kwargs and "destination_ip" not in kwargs:
        packet.pop("source_ip", None)
        packet["packet_size"] = -1
        packet["destination_port"] = "not_an_int"
        
    return packet


def create_forbidden_payload_packet(**kwargs) -> Dict[str, Any]:
    """
    Creates a synthetic packet that deliberately contains a forbidden payload.
    Used for testing the parser's fail-closed privacy guards.
    """
    packet = _base_packet(PROTOCOL_TCP, **kwargs)
    packet["payload"] = "secret_forbidden_data"
    packet["credentials"] = "admin:password123"
    return packet


def create_packet_sequence(
    flow_count: int = 1,
    packets_per_flow: int = 5,
    interval_seconds: float = 0.1,
    mixed_protocols: bool = False
) -> List[Dict[str, Any]]:
    """
    Generates a sequence of ordered synthetic packets.
    Useful for testing flow aggregation and time-based feature extraction.
    
    Args:
        flow_count: Number of distinct flows to generate (different IP/ports).
        packets_per_flow: Number of packets inside each flow.
        interval_seconds: Time gap between generated packets.
        mixed_protocols: If True, alternates protocols across flows.
    """
    sequence = []
    start_time = time.time()
    
    protocols = [PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]
    
    for f_idx in range(flow_count):
        src_ip = f"10.0.0.{10 + f_idx}"
        dst_ip = f"203.0.113.{50 + f_idx}"
        src_port = 10000 + f_idx
        dst_port = 80 + (f_idx % 2)
        
        protocol = protocols[f_idx % len(protocols)] if mixed_protocols else PROTOCOL_TCP
        
        for p_idx in range(packets_per_flow):
            current_time = start_time + (f_idx * packets_per_flow + p_idx) * interval_seconds
            
            # Simple simulation of TCP handshake if TCP
            tcp_flags = TCP_FLAG_ACK
            if protocol == PROTOCOL_TCP:
                if p_idx == 0:
                    tcp_flags = TCP_FLAG_SYN
                elif p_idx == packets_per_flow - 1:
                    tcp_flags = TCP_FLAG_FIN
                    
            packet = _base_packet(
                protocol=protocol,
                timestamp=current_time,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                tcp_flags=tcp_flags
            )
            sequence.append(packet)
            
    # Sort the sequence globally by timestamp to ensure chronological order
    sequence.sort(key=lambda p: p["timestamp"])
    return sequence
