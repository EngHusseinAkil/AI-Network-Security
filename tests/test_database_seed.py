import pytest
from database.seed import (
    seed_admin_user,
    seed_sample_devices,
    seed_sample_traffic_records,
    seed_sample_threat_logs,
    seed_sample_alerts,
    seed_sample_blocklists,
    seed_system_events,
    seed_demo_data
)
from database.repositories import (
    UserRepository, DeviceRepository, TrafficRepository, ThreatRepository,
    AlertRepository, BlocklistRepository, SystemEventRepository
)
from utils.exceptions import DatabaseError

def test_seed_admin_user(db_session):
    repo = UserRepository(db_session)
    assert repo.count() == 0
    with pytest.raises(DatabaseError):
        seed_admin_user(db_session)
    assert repo.count() == 0

def test_seed_sample_data(db_session):
    # Devices
    dev_repo = DeviceRepository(db_session)
    devices = seed_sample_devices(db_session)
    assert len(devices) > 0
    assert dev_repo.count() == len(devices)
    seed_sample_devices(db_session)
    assert dev_repo.count() == len(devices) # idempotent
    
    # Traffic
    tr_repo = TrafficRepository(db_session)
    traffic = seed_sample_traffic_records(db_session)
    assert len(traffic) > 0
    assert tr_repo.count() == len(traffic)
    seed_sample_traffic_records(db_session)
    assert tr_repo.count() == len(traffic) # idempotent
    # Verify no raw payload
    assert getattr(traffic[0], "payload", None) is None
    
    # Threats
    th_repo = ThreatRepository(db_session)
    threats = seed_sample_threat_logs(db_session, devices, traffic)
    assert len(threats) > 0
    assert th_repo.count() == len(threats)
    seed_sample_threat_logs(db_session, devices, traffic)
    assert th_repo.count() == len(threats) # idempotent
    
    # Alerts
    al_repo = AlertRepository(db_session)
    alerts = seed_sample_alerts(db_session, threats)
    assert len(alerts) > 0
    assert al_repo.count() == len(alerts)
    seed_sample_alerts(db_session, threats)
    assert al_repo.count() == len(alerts) # idempotent
    
    # Blocklists
    bl_repo = BlocklistRepository(db_session)
    seed_sample_blocklists(db_session, devices)
    assert len(bl_repo.list_active_blocked_ips()) > 0
    assert len(bl_repo.list_active_blocked_devices()) > 0
    seed_sample_blocklists(db_session, devices) # idempotent
    
    # System Events
    se_repo = SystemEventRepository(db_session)
    seed_system_events(db_session)
    assert se_repo.count() > 0
    seed_system_events(db_session) # idempotent

def test_seed_demo_data_requires_confirm(db_session):
    with pytest.raises(DatabaseError, match="Safety abort: confirm=True is required to seed demo data."):
        seed_demo_data(db_session, confirm=False)

def test_seed_demo_data_production_guard(db_session, monkeypatch):
    from config import config
    from config.settings import ProductionSettings
    monkeypatch.setattr(config, "settings", ProductionSettings())
    
    with pytest.raises(DatabaseError, match="Safety abort: Cannot seed demo data in a production environment."):
        seed_demo_data(db_session, confirm=True)
        
    user_repo = UserRepository(db_session)
    assert user_repo.count() == 0

def test_seed_demo_data_success(db_session, monkeypatch):
    from config import config
    from config.settings import DevelopmentSettings
    monkeypatch.setattr(config, "settings", DevelopmentSettings())
    
    # Ensure tables are empty initially (verifies no auto-run on import)
    user_repo = UserRepository(db_session)
    assert user_repo.count() == 0
    
    seed_demo_data(db_session, confirm=True)
    
    assert user_repo.count() == 0
    assert DeviceRepository(db_session).count() > 0
    assert TrafficRepository(db_session).count() > 0
    assert ThreatRepository(db_session).count() > 0
    assert AlertRepository(db_session).count() > 0
    assert SystemEventRepository(db_session).count() > 0
