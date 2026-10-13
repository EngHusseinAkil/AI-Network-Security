import pytest

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.errors.exceptions import ResourceNotFoundError

class FakeDeviceQueryService:
    def get_devices(self, page, page_size):
        return {
            "items": [{"id": 1, "mac_address": "00:00"}],
            "pagination": {"page": page, "page_size": page_size, "total_items": 1}
        }

    def get_device(self, device_id):
        if device_id == 99:
            raise ResourceNotFoundError("Not found")
        return {"item": {"id": device_id, "mac_address": "00:00"}}

class FakeTrafficQueryService:
    def get_traffic(self, page, page_size):
        return {
            "items": [{"id": 1, "protocol": "TCP"}],
            "pagination": {"page": page, "page_size": page_size, "total_items": 1}
        }

    def get_traffic_record(self, record_id):
        if record_id == 99:
            raise ResourceNotFoundError("Not found")
        return {"item": {"id": record_id, "protocol": "TCP"}}

class FakeThreatQueryService:
    def get_threats(self, page, page_size):
        return {
            "items": [{"id": 1, "threat_type": "scan"}],
            "pagination": {"page": page, "page_size": page_size, "total_items": 1}
        }

    def get_threat(self, threat_id):
        if threat_id == 99:
            raise ResourceNotFoundError("Not found")
        return {"item": {"id": threat_id, "threat_type": "scan"}}

@pytest.fixture
def app():
    deps = DependencyContainer()
    deps.device_query_service = FakeDeviceQueryService()
    deps.traffic_query_service = FakeTrafficQueryService()
    deps.threat_query_service = FakeThreatQueryService()

    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_list_devices(client):
    res = client.get('/api/v1/devices?page=1&page_size=5')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["pagination"]["page"] == 1
    assert data["data"]["pagination"]["page_size"] == 5
    assert len(data["data"]["items"]) == 1

def test_get_device(client):
    res = client.get('/api/v1/devices/1')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["item"]["id"] == 1

def test_get_device_not_found(client):
    res = client.get('/api/v1/devices/99')
    assert res.status_code == 404

def test_pagination_invalid_page(client):
    res = client.get('/api/v1/devices?page=abc')
    assert res.status_code == 400

def test_pagination_page_too_small(client):
    res = client.get('/api/v1/devices?page=0')
    assert res.status_code == 400

def test_pagination_invalid_size(client):
    res = client.get('/api/v1/devices?page_size=abc')
    assert res.status_code == 400

def test_pagination_size_too_small(client):
    res = client.get('/api/v1/devices?page_size=0')
    assert res.status_code == 400

def test_pagination_size_too_large(client):
    res = client.get('/api/v1/devices?page_size=999')
    assert res.status_code == 400

def test_list_traffic(client):
    res = client.get('/api/v1/traffic')
    assert res.status_code == 200

def test_get_traffic(client):
    res = client.get('/api/v1/traffic/1')
    assert res.status_code == 200

def test_get_traffic_not_found(client):
    res = client.get('/api/v1/traffic/99')
    assert res.status_code == 404

def test_list_threats(client):
    res = client.get('/api/v1/threats')
    assert res.status_code == 200

def test_get_threat(client):
    res = client.get('/api/v1/threats/1')
    assert res.status_code == 200

def test_get_threat_not_found(client):
    res = client.get('/api/v1/threats/99')
    assert res.status_code == 404
