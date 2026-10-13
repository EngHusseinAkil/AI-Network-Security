"""
Network Constants

Defines safe network constants, capture limits, and protocol mappings for the Network Engine.
These constants ensure the network engine operates safely without storing sensitive payload data.
"""

from typing import Dict, Set
from enum import Enum, auto


# --- Privacy & Safety Rules ---
# The Network Engine is strictly prohibited from capturing, parsing, or storing payload data.
# This ensures compliance with privacy standards and avoids storing sensitive credentials or tokens.
PRIVACY_PAYLOAD_EXCLUSION_RULE = (
    "Payloads MUST NOT be stored, captured, or parsed. "
    "Only L3/L4 metadata (headers, flags, sizes) is permitted."
)

# --- Capture Limits ---
# To prevent DoS or excessive memory consumption during packet capture.
DEFAULT_MAX_PACKET_SAMPLE_COUNT: int = 100000
DEFAULT_MAX_CAPTURE_DURATION_SECONDS: int = 3600  # 1 hour
MAX_SAFE_PACKET_SAMPLE_COUNT: int = 5000000

# --- Protocols ---
PROTOCOL_TCP: str = "TCP"
PROTOCOL_UDP: str = "UDP"
PROTOCOL_ICMP: str = "ICMP"
PROTOCOL_OTHER: str = "OTHER"

SUPPORTED_PROTOCOLS: Set[str] = {
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_ICMP,
    PROTOCOL_OTHER
}

# Standard IP protocol numbers mapping to string names
PROTOCOL_NUMBER_MAPPING: Dict[int, str] = {
    1: PROTOCOL_ICMP,
    6: PROTOCOL_TCP,
    17: PROTOCOL_UDP,
}

# --- TCP Flags ---
# Common TCP flag strings for easy reference and mapping
TCP_FLAG_FIN: str = "FIN"
TCP_FLAG_SYN: str = "SYN"
TCP_FLAG_RST: str = "RST"
TCP_FLAG_PSH: str = "PSH"
TCP_FLAG_ACK: str = "ACK"
TCP_FLAG_URG: str = "URG"
TCP_FLAG_ECE: str = "ECE"
TCP_FLAG_CWR: str = "CWR"

# --- Allowed Metadata Fields ---
# Explicit allowlist of metadata fields that are considered safe to extract
ALLOWED_METADATA_FIELDS: Set[str] = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_size",
    "ttl",
    "tcp_flags",
    "direction",
    "interface_name"
}


# --- Capture State Enum ---
class CaptureState(Enum):
    DISABLED = auto()
    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()
    ERROR = auto()
    UNAVAILABLE = auto()
    UNKNOWN = auto()
