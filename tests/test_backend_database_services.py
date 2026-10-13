import pytest
from unittest.mock import patch, MagicMock

from backend.services.db_services import DeviceQueryService, TrafficQueryService, ThreatQueryService
from backend.errors.exceptions import ResourceNotFoundError, InternalApiError

# Dummy classes to act as models
class DummyDevice:
    def __init__(self, id=1):
        self.id = id
        self.mac_address = "00:11:22:33:44:55"
        self.ip_address = "192.168.1.100"
        self.hostname = "test-host"
        self.is_active = True
        self.risk_score = 0.5
        self.last_seen = None
        self.created_at = None

class DummyTrafficRecord:
    def __init__(self, id=1):
        self.id = id
        self.source_ip = "192.168.1.10"
        self.destination_ip = "8.8.8.8"
        self.protocol = "TCP"
        self.byte_count = 100
        self.packet_count = 2
        self.flow_duration = 0.5
        self.captured_at = None

class DummyThreatLog:
    def __init__(self, id=1):
        self.id = id
        self.source_ip = "192.168.1.10"
        self.destination_ip = "8.8.8.8"
        self.threat_type = "port_scan"
        self.severity = "high"
        self.confidence = 0.95
        self.action_taken = "logged"
        self.detected_at = None

@pytest.fixture
def mock_session_scope():
    with patch('backend.services.db_services.session_scope') as mock_scope:
        # mock_scope.return_value.__enter__.return_value = MagicMock()
        yield mock_scope

@patch('backend.services.db_services.DeviceRepository')
def test_device_query_service_get_devices(mock_repo_class, mock_session_scope):
    mock_repo = MagicMock()
    mock_repo_class.return_value = mock_repo
    mock_repo.count.return_value = 1
    mock_repo.get_all.return_value = [DummyDevice()]

    svc = DeviceQueryService()
    res = svc.get_devices(page=1, page_size=10)

    assert res["pagination"]["total_items"] == 1
    assert len(res["items"]) == 1
    assert res["items"][0]["id"] == 1

@patch('backend.services.db_services.DeviceRepository')
def test_device_query_service_get_device(mock_repo_class, mock_session_scope):
    mock_repo = MagicMock()
    mock_repo_class.return_value = mock_repo
    mock_repo.get_by_id.return_value = DummyDevice(id=42)

    svc = DeviceQueryService()
    res = svc.get_device(42)
    assert res["item"]["id"] == 42

@patch('backend.services.db_services.DeviceRepository')
def test_device_query_service_get_device_not_found(mock_repo_class, mock_session_scope):
    mock_repo = MagicMock()
    mock_repo_class.return_value = mock_repo
    mock_repo.get_by_id.return_value = None

    svc = DeviceQueryService()
    with pytest.raises(ResourceNotFoundError):
        svc.get_device(99)

@patch('backend.services.db_services.TrafficRepository')
def test_traffic_query_service_get_traffic(mock_repo_class, mock_session_scope):
    mock_repo = MagicMock()
    mock_repo_class.return_value = mock_repo
    mock_repo.count.return_value = 1
    mock_repo.get_all.return_value = [DummyTrafficRecord()]

    svc = TrafficQueryService()
    res = svc.get_traffic(page=1, page_size=10)
    assert res["pagination"]["total_items"] == 1
    assert len(res["items"]) == 1

@patch('backend.services.db_services.ThreatRepository')
def test_threat_query_service_get_threats(mock_repo_class, mock_session_scope):
    mock_repo = MagicMock()
    mock_repo_class.return_value = mock_repo
    mock_repo.count.return_value = 1
    mock_repo.get_all.return_value = [DummyThreatLog()]

    svc = ThreatQueryService()
    res = svc.get_threats(page=1, page_size=10)
    assert res["pagination"]["total_items"] == 1
    assert len(res["items"]) == 1
