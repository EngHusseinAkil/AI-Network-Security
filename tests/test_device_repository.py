import pytest
import datetime
from database.models import Device
from database.repositories.device_repository import DeviceRepository
from utils.time_utils import get_current_utc_time

def test_device_repository_queries(db_session):
    repo = DeviceRepository(db_session)
    now = get_current_utc_time()
    
    repo.add(Device(mac_address="00:11:22:33:44:55", ip_address="192.168.1.10", risk_score=85.0, last_seen=now))
    repo.add(Device(mac_address="AA:BB:CC:DD:EE:FF", ip_address="10.0.0.5", risk_score=20.0, last_seen=now - datetime.timedelta(days=2)))
    
    # By MAC
    dev = repo.get_by_mac_address("00:11:22:33:44:55")
    assert dev is not None
    assert dev.ip_address == "192.168.1.10"
    
    # By IP
    dev2 = repo.get_by_ip_address("10.0.0.5")
    assert dev2 is not None
    assert dev2.mac_address == "AA:BB:CC:DD:EE:FF"
    
    # High risk
    high_risk = repo.list_high_risk_devices(risk_threshold=80.0)
    assert len(high_risk) == 1
    assert high_risk[0].mac_address == "00:11:22:33:44:55"
    
    # Recently seen
    recent = repo.list_recently_seen_devices(since=now - datetime.timedelta(days=1))
    assert len(recent) == 1
    assert recent[0].mac_address == "00:11:22:33:44:55"
