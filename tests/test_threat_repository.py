import pytest
import datetime
from database.models import ThreatLog
from database.repositories.threat_repository import ThreatRepository
from utils.time_utils import get_current_utc_time

def test_threat_repository_queries(db_session):
    repo = ThreatRepository(db_session)
    now = get_current_utc_time()
    
    repo.add(ThreatLog(threat_type="port_scan", severity="high", source_ip="10.0.0.5", destination_ip="10.0.0.1", detected_at=now))
    repo.add(ThreatLog(threat_type="ddos", severity="critical", source_ip="10.0.0.6", destination_ip="10.0.0.1", detected_at=now - datetime.timedelta(hours=1)))
    
    # By severity
    high_threats = repo.query_by_severity("high")
    assert len(high_threats) == 1
    assert high_threats[0].threat_type == "port_scan"
    
    # By type
    ddos_threats = repo.query_by_threat_type("ddos")
    assert len(ddos_threats) == 1
    
    # By source IP
    source_threats = repo.query_by_source_ip("10.0.0.6")
    assert len(source_threats) == 1
    assert source_threats[0].severity == "critical"
    
    # Count by severity
    assert repo.count_by_severity("critical") == 1
