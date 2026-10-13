"""
Flow Aggregation Engine.

Aggregates parsed `PacketMetadata` objects into safe `FlowMetadata` summaries 
without storing packet payloads or using live capture.
"""

import time
from typing import Dict, List, Optional

from network.metadata import PacketMetadata, FlowMetadata, FlowKey


def create_flow_key(packet: PacketMetadata) -> FlowKey:
    """
    Extracts a FlowKey from a PacketMetadata object.
    The underlying get_flow_key() method guarantees safe creation.
    """
    if not isinstance(packet, PacketMetadata):
        raise ValueError("packet must be a PacketMetadata instance")
    return packet.get_flow_key()


def update_flow(flow: FlowMetadata, packet: PacketMetadata) -> None:
    """
    Updates an existing FlowMetadata object in-place with new packet statistics.
    Handles out-of-order timestamps and prevents negative values.
    """
    if not isinstance(flow, FlowMetadata):
        raise ValueError("flow must be a FlowMetadata instance")
    if not isinstance(packet, PacketMetadata):
        raise ValueError("packet must be a PacketMetadata instance")
        
    packet_size = max(0, packet.packet_size)
    
    # Update packet counts and bytes
    flow.packet_count += 1
    flow.byte_count += packet_size
    
    # Update min/max size
    if flow.packet_count == 1:
        flow.min_packet_size = packet_size
        flow.max_packet_size = packet_size
    else:
        flow.min_packet_size = min(flow.min_packet_size, packet_size)
        flow.max_packet_size = max(flow.max_packet_size, packet_size)
        
    # Update average size
    flow.avg_packet_size = flow.byte_count / flow.packet_count
    
    # Update timestamps (handling out-of-order packets)
    flow.start_time = min(flow.start_time, packet.timestamp)
    flow.end_time = max(flow.end_time, packet.timestamp)
    
    # Update duration safely
    flow.duration = max(0.0, flow.end_time - flow.start_time)
    
    # Update direction if unknown, or overwrite if new packet provides direction 
    # and previous was unknown (in robust systems, direction could be stateful, 
    # but here we follow the packet's assigned direction, ideally it's consistent).
    if packet.direction != "unknown":
        flow.direction = packet.direction


class FlowAggregator:
    """
    Aggregates PacketMetadata into stateful FlowMetadata objects.
    Provides methods to retrieve active flows safely.
    """
    
    def __init__(self):
        self._flows: Dict[FlowKey, FlowMetadata] = {}
        
    def add_packet(self, packet: PacketMetadata) -> FlowMetadata:
        """
        Consumes a PacketMetadata object, either creating a new flow 
        or updating an existing one. Returns the aggregated FlowMetadata.
        """
        if not isinstance(packet, PacketMetadata):
            raise ValueError("packet must be a PacketMetadata instance")
            
        key = create_flow_key(packet)
        
        if key not in self._flows:
            # Create new flow
            flow = FlowMetadata(
                flow_key=key,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
                packet_count=0,
                byte_count=0,
                min_packet_size=0,
                max_packet_size=0,
                avg_packet_size=0.0,
                direction=packet.direction
            )
            self._flows[key] = flow
            
        # Update flow stats
        update_flow(self._flows[key], packet)
        return self._flows[key]
        
    def get_flow(self, flow_key: FlowKey) -> Optional[FlowMetadata]:
        """Retrieves a specific flow by its FlowKey."""
        return self._flows.get(flow_key)
        
    def get_all_flows(self) -> List[FlowMetadata]:
        """Returns a list of all aggregated flows."""
        return list(self._flows.values())
        
    def get_recent_flows(self, limit: int = 100) -> List[FlowMetadata]:
        """
        Returns the most recently updated flows, up to the given limit.
        Sorted by end_time descending (most recent first).
        """
        if not isinstance(limit, int) or limit < 0:
            limit = 100
            
        all_flows = self.get_all_flows()
        all_flows.sort(key=lambda f: f.end_time, reverse=True)
        return all_flows[:limit]
        
    def reset(self) -> None:
        """Clears all tracked flows from memory."""
        self._flows.clear()
