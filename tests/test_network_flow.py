"""
Tests for Flow Aggregation Engine.
Ensures correct aggregation of PacketMetadata into FlowMetadata 
without payloads or live capture.
"""

import pytest
import time

from network.metadata import PacketMetadata, FlowMetadata, FlowKey
from network.parser import parse_packet
from network.synthetic import (
    create_tcp_packet,
    create_udp_packet,
    create_icmp_packet,
    create_packet_sequence
)
from network.flow import (
    create_flow_key,
    update_flow,
    FlowAggregator
)


def _generate_parsed_packet(factory_func, **kwargs) -> PacketMetadata:
    """Helper to generate and parse a safe packet."""
    raw_dict = factory_func(**kwargs)
    return parse_packet(raw_dict)


def test_create_flow_key():
    """Verify flow key extraction."""
    packet = _generate_parsed_packet(
        create_tcp_packet, 
        source_ip="192.168.1.5", 
        destination_ip="8.8.8.8",
        source_port=1234,
        destination_port=80
    )
    
    key = create_flow_key(packet)
    assert isinstance(key, FlowKey)
    assert key.source_ip == "192.168.1.5"
    assert key.destination_ip == "8.8.8.8"
    assert key.source_port == 1234
    assert key.destination_port == 80
    assert key.protocol == "TCP"


def test_update_flow_statistics():
    """Verify flow statistics calculate correctly (counts, bytes, averages, sizes)."""
    packet1 = _generate_parsed_packet(create_tcp_packet, packet_size=100, timestamp=10.0)
    packet2 = _generate_parsed_packet(create_tcp_packet, packet_size=300, timestamp=12.0)
    packet3 = _generate_parsed_packet(create_tcp_packet, packet_size=50, timestamp=15.0)
    
    key = create_flow_key(packet1)
    flow = FlowMetadata(key, start_time=packet1.timestamp, end_time=packet1.timestamp)
    
    # Process 1
    update_flow(flow, packet1)
    assert flow.packet_count == 1
    assert flow.byte_count == 100
    assert flow.min_packet_size == 100
    assert flow.max_packet_size == 100
    assert flow.avg_packet_size == 100.0
    assert flow.duration == 0.0
    
    # Process 2
    update_flow(flow, packet2)
    assert flow.packet_count == 2
    assert flow.byte_count == 400
    assert flow.min_packet_size == 100
    assert flow.max_packet_size == 300
    assert flow.avg_packet_size == 200.0
    assert flow.duration == 2.0
    
    # Process 3
    update_flow(flow, packet3)
    assert flow.packet_count == 3
    assert flow.byte_count == 450
    assert flow.min_packet_size == 50
    assert flow.max_packet_size == 300
    assert flow.avg_packet_size == 150.0
    assert flow.duration == 5.0
    
    # Verify no payloads snuck in
    assert not hasattr(flow, 'payload')
    assert not hasattr(flow, 'raw_payload')


def test_update_flow_out_of_order():
    """Verify out-of-order timestamps expand the flow window properly."""
    packet_middle = _generate_parsed_packet(create_tcp_packet, timestamp=10.0)
    packet_early = _generate_parsed_packet(create_tcp_packet, timestamp=5.0)
    packet_late = _generate_parsed_packet(create_tcp_packet, timestamp=20.0)
    
    key = create_flow_key(packet_middle)
    flow = FlowMetadata(key, start_time=packet_middle.timestamp, end_time=packet_middle.timestamp)
    
    update_flow(flow, packet_middle)
    assert flow.start_time == 10.0
    assert flow.end_time == 10.0
    
    update_flow(flow, packet_early)
    assert flow.start_time == 5.0  # Window expanded backward
    assert flow.end_time == 10.0
    assert flow.duration == 5.0
    
    update_flow(flow, packet_late)
    assert flow.start_time == 5.0
    assert flow.end_time == 20.0  # Window expanded forward
    assert flow.duration == 15.0


def test_flow_aggregator_single_flow():
    """Verify aggregator groups identical packets into one flow."""
    aggregator = FlowAggregator()
    
    p1 = _generate_parsed_packet(create_tcp_packet, source_ip="1.1.1.1", destination_ip="2.2.2.2", source_port=1000, destination_port=80, packet_size=100)
    p2 = _generate_parsed_packet(create_tcp_packet, source_ip="1.1.1.1", destination_ip="2.2.2.2", source_port=1000, destination_port=80, packet_size=200)
    
    f1 = aggregator.add_packet(p1)
    f2 = aggregator.add_packet(p2)
    
    assert f1 is f2  # Same object reference
    assert len(aggregator.get_all_flows()) == 1
    
    flow = aggregator.get_all_flows()[0]
    assert flow.packet_count == 2
    assert flow.byte_count == 300


def test_flow_aggregator_multi_flow():
    """Verify aggregator separates distinct flows."""
    aggregator = FlowAggregator()
    
    p_tcp = _generate_parsed_packet(create_tcp_packet, source_ip="1.1.1.1", destination_ip="2.2.2.2")
    p_udp = _generate_parsed_packet(create_udp_packet, source_ip="1.1.1.1", destination_ip="2.2.2.2")
    p_tcp_diff_ip = _generate_parsed_packet(create_tcp_packet, source_ip="3.3.3.3", destination_ip="2.2.2.2")
    
    aggregator.add_packet(p_tcp)
    aggregator.add_packet(p_udp)
    aggregator.add_packet(p_tcp_diff_ip)
    
    assert len(aggregator.get_all_flows()) == 3


def test_flow_aggregator_icmp():
    """Verify aggregator works for ICMP (which lacks ports)."""
    aggregator = FlowAggregator()
    p_icmp = _generate_parsed_packet(create_icmp_packet, source_ip="1.1.1.1", destination_ip="2.2.2.2")
    
    flow = aggregator.add_packet(p_icmp)
    assert flow.packet_count == 1
    assert flow.protocol == "ICMP"
    assert flow.flow_key.source_port is None
    assert flow.flow_key.destination_port is None


def test_flow_aggregator_recent_flows():
    """Verify get_recent_flows limits and sorts properly."""
    aggregator = FlowAggregator()
    
    # Add 5 distinct flows with different end_times
    for i in range(5):
        p = _generate_parsed_packet(
            create_tcp_packet, 
            source_port=1000+i, 
            timestamp=10.0 + i  # Ascending timestamps
        )
        aggregator.add_packet(p)
        
    recent = aggregator.get_recent_flows(limit=3)
    assert len(recent) == 3
    
    # Should be sorted descending by end_time (most recent first)
    assert recent[0].end_time == 14.0
    assert recent[1].end_time == 13.0
    assert recent[2].end_time == 12.0


def test_flow_aggregator_reset():
    """Verify reset clears state."""
    aggregator = FlowAggregator()
    p = _generate_parsed_packet(create_tcp_packet)
    aggregator.add_packet(p)
    
    assert len(aggregator.get_all_flows()) == 1
    
    aggregator.reset()
    assert len(aggregator.get_all_flows()) == 0


def test_sequence_aggregation():
    """Verify aggregation over a complex generated synthetic sequence."""
    raw_seq = create_packet_sequence(flow_count=3, packets_per_flow=4, interval_seconds=0.5, mixed_protocols=True)
    
    aggregator = FlowAggregator()
    for raw_pkt in raw_seq:
        parsed = parse_packet(raw_pkt)
        aggregator.add_packet(parsed)
        
    flows = aggregator.get_all_flows()
    assert len(flows) == 3
    
    for flow in flows:
        assert flow.packet_count == 4
        assert flow.duration == 1.5  # (4 packets - 1) * 0.5 sec intervals
