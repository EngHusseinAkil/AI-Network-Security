"""
Packet Metadata Parser.

Provides a safe, payload-free packet parsing layer. Converts synthetic or 
adapter-provided packet representations (dictionaries) into the structured 
`PacketMetadata` dataclass.

Strictly excludes payload extraction.
"""

from typing import Dict, Any, List, Optional
import time

from network.metadata import PacketMetadata
from network.constants import (
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_ICMP,
    PROTOCOL_OTHER,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
    TCP_FLAG_PSH,
    TCP_FLAG_URG,
    TCP_FLAG_ECE,
    TCP_FLAG_CWR
)
from network.interfaces import validate_interface_name


# Forbidden keys that must trigger a rejection if found in a synthetic packet.
FORBIDDEN_PAYLOAD_KEYS = {
    "payload", "raw_payload", "body", "http_body", 
    "credentials", "tokens", "cookie", "data", "raw_bytes"
}

def validate_packet_structure(packet: Dict[str, Any]) -> None:
    """
    Validates that the input dictionary does not contain forbidden payload fields.
    Fails closed: if any forbidden key is present, a ValueError is raised.
    """
    if not isinstance(packet, dict):
        raise ValueError("Packet representation must be a dictionary.")
    
    # Check for forbidden keys (case-insensitive for safety)
    packet_keys_lower = {str(k).lower() for k in packet.keys()}
    for forbidden in FORBIDDEN_PAYLOAD_KEYS:
        if forbidden in packet_keys_lower:
            # We explicitly do NOT log the value of the forbidden field.
            raise ValueError(f"CRITICAL PRIVACY VIOLATION: Packet dictionary contains forbidden key '{forbidden}'.")


def extract_tcp_flags(packet: Dict[str, Any]) -> str:
    """
    Extracts and normalizes TCP flags from the packet dictionary.
    Expects a list of flag strings or a single string.
    """
    flags_val = packet.get("tcp_flags")
    if not flags_val:
        return ""
    
    if isinstance(flags_val, str):
        flags = [f.strip().upper() for f in flags_val.split(",")]
    elif isinstance(flags_val, list):
        flags = [str(f).strip().upper() for f in flags_val]
    else:
        return ""
        
    normalized = []
    # Only allow safe known flags
    safe_flags = {
        "SYN": TCP_FLAG_SYN, "ACK": TCP_FLAG_ACK, "FIN": TCP_FLAG_FIN, 
        "RST": TCP_FLAG_RST, "PSH": TCP_FLAG_PSH, "URG": TCP_FLAG_URG, 
        "ECE": TCP_FLAG_ECE, "CWR": TCP_FLAG_CWR
    }
    
    for f in flags:
        if f in safe_flags:
            normalized.append(safe_flags[f])
            
    return ",".join(normalized)


def determine_direction(source_ip: str, destination_ip: str, local_addresses: set[str]) -> str:
    """
    Determines the direction of the traffic based on local address sets.
    
    Rules:
    - internal: Both source and destination are in local_addresses.
    - outbound: Source is in local_addresses, destination is not.
    - inbound: Destination is in local_addresses, source is not.
    - external: Neither source nor destination are in local_addresses.
    - unknown: IPs are missing.
    """
    if not source_ip or not destination_ip:
        return "unknown"
        
    src_local = source_ip in local_addresses
    dst_local = destination_ip in local_addresses
    
    if src_local and dst_local:
        return "internal"
    elif src_local and not dst_local:
        return "outbound"
    elif not src_local and dst_local:
        return "inbound"
    else:
        return "external"


def detect_protocol(packet: Dict[str, Any]) -> str:
    """Detects the protocol string from the packet dictionary."""
    proto = str(packet.get("protocol", "")).upper()
    if proto in [PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]:
        return proto
    return PROTOCOL_OTHER


def parse_packet(packet: Dict[str, Any], local_addresses: Optional[set[str]] = None) -> PacketMetadata:
    """
    Parses a safe synthetic packet dictionary into a PacketMetadata dataclass.
    Validates payload exclusion, extracts metadata safely, normalizes TCP flags,
    and assigns a direction.
    """
    validate_packet_structure(packet)
    
    if local_addresses is None:
        local_addresses = set()
        
    source_ip = packet.get("source_ip")
    destination_ip = packet.get("destination_ip")
    
    if not source_ip or not destination_ip:
        raise ValueError("Missing required IP addresses.")
        
    protocol = detect_protocol(packet)
    
    # Parse ports
    source_port = packet.get("source_port")
    destination_port = packet.get("destination_port")
    
    if protocol in [PROTOCOL_TCP, PROTOCOL_UDP]:
        if source_port is None or destination_port is None:
             raise ValueError(f"Ports are required for protocol {protocol}.")
        try:
            source_port = int(source_port)
            destination_port = int(destination_port)
        except ValueError:
            raise ValueError("Ports must be integers.")
    else:
        source_port = None
        destination_port = None

    packet_size = packet.get("packet_size", 0)
    try:
        packet_size = int(packet_size)
        if packet_size < 0:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("Invalid packet_size. Must be a non-negative integer.")
        
    ttl = packet.get("ttl", 64)
    try:
        ttl = int(ttl)
        if not (0 <= ttl <= 255):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("Invalid TTL. Must be between 0 and 255.")
        
    timestamp = packet.get("timestamp")
    if timestamp is None:
        timestamp = time.time()
    else:
        try:
            timestamp = float(timestamp)
            if timestamp <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("Invalid timestamp.")
            
    interface_name = packet.get("interface_name", "unknown")
    if not validate_interface_name(interface_name):
        raise ValueError("Invalid interface name.")
        
    tcp_flags = ""
    if protocol == PROTOCOL_TCP:
        tcp_flags = extract_tcp_flags(packet)
        
    direction = determine_direction(source_ip, destination_ip, local_addresses)
    
    return PacketMetadata(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packet_size=packet_size,
        ttl=ttl,
        tcp_flags=tcp_flags,
        direction=direction,
        interface_name=interface_name
    )
