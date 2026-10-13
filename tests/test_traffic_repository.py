import pytest
import datetime
from database.models import TrafficRecord
from database.repositories.traffic_repository import TrafficRepository
from utils.time_utils import get_current_utc_time

def test_traffic_repository_queries(db_session):
    repo = TrafficRepository(db_session)
    now = get_current_utc_time()
    
    repo.add(TrafficRecord(
        source_ip="10.0.0.1", destination_ip="10.0.0.2",
        source_port=1234, destination_port=80, protocol="TCP",
        captured_at=now
    ))
    repo.add(TrafficRecord(
        source_ip="10.0.0.3", destination_ip="10.0.0.1",
        source_port=5678, destination_port=443, protocol="TCP",
        captured_at=now - datetime.timedelta(hours=1)
    ))
    
    # By source IP
    source_traffic = repo.query_by_source_ip("10.0.0.1")
    assert len(source_traffic) == 1
    assert source_traffic[0].destination_port == 80
    
    # By destination IP
    dest_traffic = repo.query_by_destination_ip("10.0.0.1")
    assert len(dest_traffic) == 1
    assert dest_traffic[0].source_port == 5678
    
    # By protocol
    tcp_traffic = repo.query_by_protocol("TCP")
    assert len(tcp_traffic) == 2
    
    # Time range
    range_traffic = repo.query_within_time_range(now - datetime.timedelta(minutes=5), now + datetime.timedelta(minutes=5))
    assert len(range_traffic) == 1
    
    # Count
    count = repo.count_within_time_range(now - datetime.timedelta(days=1), now + datetime.timedelta(days=1))
    assert count == 2
