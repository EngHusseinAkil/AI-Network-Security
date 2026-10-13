"""
Network Database Exporter.

Converts safe network metadata/flow summaries into database-ready records
using the existing database models and repository layer.
Strictly requires an active database session and relies on the caller to commit.
"""

from typing import List, Dict, Any
import datetime

from sqlalchemy.orm import Session

from database.models.traffic_record import TrafficRecord
from database.repositories.traffic_repository import TrafficRepository
from network.metadata import PacketMetadata, FlowMetadata
from network.features import extract_packet_features, extract_flow_features


def packet_to_traffic_record_data(packet: PacketMetadata) -> Dict[str, Any]:
    """
    Converts a single PacketMetadata object into a dictionary mapping 
    matching the TrafficRecord database schema.
    Extracts purely numerical ML features without raw payloads.
    """
    if not isinstance(packet, PacketMetadata):
        raise ValueError("packet must be a PacketMetadata instance")
        
    features = extract_packet_features(packet)
    
    # Map port values to 0 if None (for ICMP), as the DB requires integer ports.
    # Note: Port 0 here means "not applicable/not available" for portless protocols.
    # It MUST NOT be treated as an observed transport-layer port in downstream AI logic.
    # FUTURE SCHEMA IMPROVEMENT: Recommend changing TrafficRecord.source_port and 
    # destination_port to be nullable (Integer, nullable=True) in a future schema migration.
    src_port = packet.source_port if packet.source_port is not None else 0
    dst_port = packet.destination_port if packet.destination_port is not None else 0
    
    return {
        "source_ip": packet.source_ip,
        "destination_ip": packet.destination_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": packet.protocol,
        "packet_size": packet.packet_size,
        "flow_duration": 0.0,
        "packet_count": 1,
        "byte_count": packet.packet_size,
        "extracted_features": features,
        # Convert unix timestamp to timezone-aware UTC datetime
        "captured_at": datetime.datetime.fromtimestamp(packet.timestamp, tz=datetime.timezone.utc)
    }


def flow_to_traffic_record_data(flow: FlowMetadata) -> Dict[str, Any]:
    """
    Converts a FlowMetadata object into a dictionary mapping 
    matching the TrafficRecord database schema.
    Extracts purely numerical ML features without raw payloads.
    """
    if not isinstance(flow, FlowMetadata):
        raise ValueError("flow must be a FlowMetadata instance")
        
    features = extract_flow_features(flow)
    
    # Note: Port 0 here means "not applicable/not available" for portless protocols.
    # It MUST NOT be treated as an observed transport-layer port in downstream AI logic.
    # FUTURE SCHEMA IMPROVEMENT: Recommend changing TrafficRecord.source_port and 
    # destination_port to be nullable (Integer, nullable=True) in a future schema migration.
    src_port = flow.flow_key.source_port if flow.flow_key.source_port is not None else 0
    dst_port = flow.flow_key.destination_port if flow.flow_key.destination_port is not None else 0
    
    return {
        "source_ip": flow.flow_key.source_ip,
        "destination_ip": flow.flow_key.destination_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": flow.protocol,
        "packet_size": flow.avg_packet_size,  # Store average size as packet_size for the flow summary
        "flow_duration": flow.duration,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "extracted_features": features,
        # Store the end_time of the flow as the captured_at time
        "captured_at": datetime.datetime.fromtimestamp(flow.end_time, tz=datetime.timezone.utc)
    }


def export_packet_metadata(session: Session, packet: PacketMetadata) -> TrafficRecord:
    """
    Converts and adds a PacketMetadata to the session via TrafficRepository.
    Does NOT commit the session.
    """
    if not isinstance(session, Session):
        raise ValueError("A valid SQLAlchemy Session is required.")
        
    data = packet_to_traffic_record_data(packet)
    record = TrafficRecord(**data)
    repo = TrafficRepository(session)
    return repo.add(record)


def export_flow_metadata(session: Session, flow: FlowMetadata) -> TrafficRecord:
    """
    Converts and adds a FlowMetadata to the session via TrafficRepository.
    Does NOT commit the session.
    """
    if not isinstance(session, Session):
        raise ValueError("A valid SQLAlchemy Session is required.")
        
    data = flow_to_traffic_record_data(flow)
    record = TrafficRecord(**data)
    repo = TrafficRepository(session)
    return repo.add(record)


def export_flows(session: Session, flows: List[FlowMetadata], limit: int = 100) -> List[TrafficRecord]:
    """
    Bulk exports a list of FlowMetadata to the session.
    Enforces a limit to prevent memory/database floods.
    Does NOT commit the session.
    """
    if not isinstance(session, Session):
        raise ValueError("A valid SQLAlchemy Session is required.")
        
    if not isinstance(flows, list):
        raise ValueError("flows must be a list of FlowMetadata")
        
    safe_limit = max(1, limit)
    records = []
    repo = TrafficRepository(session)
    
    for flow in flows[:safe_limit]:
        data = flow_to_traffic_record_data(flow)
        record = TrafficRecord(**data)
        repo.add(record)
        records.append(record)
        
    return records
