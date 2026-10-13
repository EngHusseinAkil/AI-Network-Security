"""
Tests for Network Database Exporter.
Ensures network metadata translates correctly to the TrafficRecord schema 
and that no payloads or hidden commits occur.
"""

import pytest

from network.constants import PROTOCOL_TCP, PROTOCOL_ICMP
from network.parser import parse_packet
from network.synthetic import create_tcp_packet, create_icmp_packet
from network.flow import FlowAggregator
from network.exporter import (
    packet_to_traffic_record_data,
    flow_to_traffic_record_data,
    export_packet_metadata,
    export_flow_metadata,
    export_flows
)
from database.models.traffic_record import TrafficRecord


def _generate_parsed_packet(factory_func, **kwargs):
    raw_dict = factory_func(**kwargs)
    return parse_packet(raw_dict)


def test_packet_to_traffic_record_data():
    """Verify dictionary conversion maps fields properly."""
    packet = _generate_parsed_packet(
        create_tcp_packet,
        source_ip="192.168.1.5",
        destination_port=443,
        packet_size=500
    )
    
    data = packet_to_traffic_record_data(packet)
    
    assert data["source_ip"] == "192.168.1.5"
    assert data["destination_port"] == 443
    assert data["protocol"] == PROTOCOL_TCP
    assert data["packet_size"] == 500
    assert data["flow_duration"] == 0.0
    assert data["packet_count"] == 1
    assert data["byte_count"] == 500
    
    # Feature extraction should populate dictionary
    assert isinstance(data["extracted_features"], dict)
    assert data["extracted_features"]["protocol_enc"] == 1
    assert "payload" not in data
    
    # Datetime should be timezone-aware UTC
    assert data["captured_at"].tzinfo is not None


def test_packet_to_traffic_record_data_icmp():
    """Verify ICMP packet missing ports defaults to 0 safely for DB schema."""
    packet = _generate_parsed_packet(create_icmp_packet)
    data = packet_to_traffic_record_data(packet)
    
    assert data["protocol"] == PROTOCOL_ICMP
    assert data["source_port"] == 0
    assert data["destination_port"] == 0


def test_flow_to_traffic_record_data():
    """Verify flow summaries map fields properly."""
    aggregator = FlowAggregator()
    aggregator.add_packet(_generate_parsed_packet(create_tcp_packet, packet_size=100))
    flow = aggregator.add_packet(_generate_parsed_packet(create_tcp_packet, packet_size=300))
    
    data = flow_to_traffic_record_data(flow)
    
    assert data["packet_count"] == 2
    assert data["byte_count"] == 400
    assert data["packet_size"] == 200.0  # mapped to average size
    assert data["protocol"] == PROTOCOL_TCP
    
    assert isinstance(data["extracted_features"], dict)
    assert data["extracted_features"]["packet_count"] == 2


def test_export_packet_metadata(db_session):
    """Verify actual database insertion of a packet."""
    packet = _generate_parsed_packet(create_tcp_packet, source_ip="10.10.10.10")
    
    record = export_packet_metadata(db_session, packet)
    
    assert isinstance(record, TrafficRecord)
    assert record.id is not None  # ID is populated by session.flush() in BaseRepository
    
    # Prove the session tracks it
    db_session.commit()
    assert record.id is not None
    assert record.source_ip == "10.10.10.10"


def test_export_flow_metadata(db_session):
    """Verify actual database insertion of a flow."""
    aggregator = FlowAggregator()
    flow = aggregator.add_packet(_generate_parsed_packet(create_tcp_packet, source_ip="10.10.10.20"))
    
    record = export_flow_metadata(db_session, flow)
    
    assert isinstance(record, TrafficRecord)
    assert record.id is not None
    
    db_session.commit()
    assert record.id is not None
    assert record.source_ip == "10.10.10.20"
    assert record.packet_count == 1


def test_export_flows_bulk(db_session):
    """Verify bulk flow insertion and limit enforcement."""
    aggregator = FlowAggregator()
    
    # Create 5 distinct flows
    for i in range(5):
        aggregator.add_packet(_generate_parsed_packet(create_tcp_packet, source_port=1000+i))
        
    flows = aggregator.get_all_flows()
    assert len(flows) == 5
    
    # Export with limit 3
    records = export_flows(db_session, flows, limit=3)
    
    assert len(records) == 3
    db_session.commit()
    
    # Query db to verify only 3 records exist
    db_records = db_session.query(TrafficRecord).all()
    assert len(db_records) == 3


def test_exporter_rejects_invalid_inputs(db_session):
    """Verify exceptions are raised for bad arguments."""
    with pytest.raises(ValueError):
        export_packet_metadata(None, _generate_parsed_packet(create_tcp_packet))
        
    with pytest.raises(ValueError):
        export_packet_metadata(db_session, "not_a_packet")
        
    with pytest.raises(ValueError):
        export_flows(db_session, "not_a_list")
