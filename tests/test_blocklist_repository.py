import pytest
import datetime
from database.models import BlockedIP, BlockedDevice
from database.repositories.blocklist_repository import BlocklistRepository
from utils.time_utils import get_current_utc_time

def test_blocklist_repository_ip_blocks(db_session):
    repo = BlocklistRepository(db_session)
    now = get_current_utc_time()
    
    # Active IP block
    ip_block = BlockedIP(ip_address="192.168.1.100", reason="spam", severity="high", blocked_at=now, is_active=True)
    repo.add_ip_block(ip_block)
    
    # Expired IP block
    expired_ip = BlockedIP(ip_address="10.0.0.5", reason="scan", severity="medium", blocked_at=now - datetime.timedelta(days=2), expires_at=now - datetime.timedelta(days=1), is_active=True)
    repo.add_ip_block(expired_ip)
    
    # Inactive IP block
    inactive_ip = BlockedIP(ip_address="172.16.0.1", reason="manual", severity="low", blocked_at=now, is_active=False)
    repo.add_ip_block(inactive_ip)
    
    active = repo.find_active_ip_block("192.168.1.100")
    assert active is not None
    
    assert repo.find_active_ip_block("10.0.0.5") is None
    assert repo.find_active_ip_block("172.16.0.1") is None
    
    active_list = repo.list_active_blocked_ips()
    assert len(active_list) == 1
    assert active_list[0].ip_address == "192.168.1.100"

def test_blocklist_repository_device_blocks(db_session):
    repo = BlocklistRepository(db_session)
    now = get_current_utc_time()
    
    dev_block = BlockedDevice(mac_address="AA:BB:CC:11:22:33", reason="malware", severity="critical", blocked_at=now, is_active=True)
    repo.add_device_block(dev_block)
    
    active = repo.find_active_device_block("AA:BB:CC:11:22:33")
    assert active is not None
    
    assert repo.is_block_expired(dev_block) is False
    
    dev_block.expires_at = now - datetime.timedelta(hours=1)
    assert repo.is_block_expired(dev_block) is True
