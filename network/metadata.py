"""
Network Metadata Dataclasses.

Provides safe, payload-free network data structures that future packet parsing,
flow aggregation, and feature extraction modules will use.
Strictly excludes any raw payload, bodies, or sensitive tokens.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any

from utils.validators import validate_string


@dataclass(frozen=True)
class FlowKey:
    """
    Uniquely identifies a network flow using safe metadata.
    This class is hashable and can be used as a dictionary key for stateful flow tracking.
    """
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str

    def __post_init__(self):
        """Validate basic fields upon creation."""
        if not validate_string(self.source_ip):
            raise ValueError(f"Invalid source_ip: {self.source_ip}")
        if not validate_string(self.destination_ip):
            raise ValueError(f"Invalid destination_ip: {self.destination_ip}")
        if not validate_string(self.protocol):
            raise ValueError(f"Invalid protocol: {self.protocol}")
        if self.source_port is not None and not (0 <= self.source_port <= 65535):
            raise ValueError(f"Invalid source_port: {self.source_port}")
        if self.destination_port is not None and not (0 <= self.destination_port <= 65535):
            raise ValueError(f"Invalid destination_port: {self.destination_port}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def __str__(self) -> str:
        """Safe string representation without payloads."""
        return f"{self.protocol} {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"


@dataclass
class PacketMetadata:
    """
    Safe packet metadata extracted from a raw network frame.
    Strictly forbids raw_payload, packet_body, or credentials.
    """
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_size: int
    ttl: int
    tcp_flags: str = ""
    direction: str = "outbound"
    interface_name: str = "unknown"

    def __post_init__(self):
        """Validate core fields."""
        if not validate_string(self.source_ip):
            raise ValueError(f"Invalid source_ip: {self.source_ip}")
        if not validate_string(self.destination_ip):
            raise ValueError(f"Invalid destination_ip: {self.destination_ip}")
        if not validate_string(self.protocol):
            raise ValueError(f"Invalid protocol: {self.protocol}")
        
        # Explicitly guard against adding payload-related attributes dynamically
        invalid_attrs = ["raw_payload", "payload", "packet_body", "http_body", "credentials", "tokens", "dns_query_content"]
        for attr in invalid_attrs:
            if hasattr(self, attr):
                raise ValueError(f"CRITICAL PRIVACY VIOLATION: PacketMetadata cannot contain '{attr}'")

    def get_flow_key(self) -> FlowKey:
        """Generate the FlowKey for this packet."""
        return FlowKey(
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            source_port=self.source_port,
            destination_port=self.destination_port,
            protocol=self.protocol
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def __str__(self) -> str:
        """Safe string representation."""
        return (f"[{self.timestamp}] {self.protocol} {self.source_ip}:{self.source_port} -> "
                f"{self.destination_ip}:{self.destination_port} (Size: {self.packet_size}, Flags: {self.tcp_flags})")


@dataclass
class FlowMetadata:
    """
    Aggregated metadata for a specific network flow over time.
    """
    flow_key: FlowKey
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    min_packet_size: int = 0
    max_packet_size: int = 0
    avg_packet_size: float = 0.0
    duration: float = 0.0
    protocol: str = field(init=False)
    direction: str = "outbound"

    def __post_init__(self):
        """Derive attributes from flow_key."""
        self.protocol = self.flow_key.protocol
        
        if self.end_time < self.start_time:
            raise ValueError("end_time cannot be before start_time")
        self.duration = self.end_time - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, unrolling the flow_key for easy JSON serialization."""
        data = asdict(self)
        data.update(self.flow_key.to_dict())
        del data['flow_key']
        return data

    def __str__(self) -> str:
        """Safe string representation."""
        return (f"Flow: {self.flow_key} | Packets: {self.packet_count} | Bytes: {self.byte_count} | Duration: {self.duration:.2f}s")


@dataclass
class InterfaceMetadata:
    """
    Metadata for discovered network interfaces.
    """
    name: str
    description: str = ""
    is_up: bool = False
    mac_address: str = ""
    ip_addresses: list[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def __str__(self) -> str:
        """Safe string representation."""
        status = "UP" if self.is_up else "DOWN"
        return f"Interface {self.name} [{status}] - MAC: {self.mac_address}"
