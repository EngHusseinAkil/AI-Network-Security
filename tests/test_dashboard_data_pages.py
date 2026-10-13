import pytest
from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.errors.exceptions import ResourceNotFoundError

class FakeModelService:
    def get_available_models(self):
        return [{"model_version": "v1.0"}]
    def get_active_model_metadata(self):
        return {"model_version": "v1.0"}

class FakeDeviceQueryService:
    def get_devices(self, page, page_size):
        return {"items": [{"id": "test_id"}], "total": 1}
    def get_device_by_id(self, device_id):
        if device_id == "non_existent_id":
            return None
        return {"id": device_id}

class FakeTrafficQueryService:
    def get_recent_traffic(self, page, page_size):
        return {"items": [], "total": 0}
    def get_traffic_by_id(self, record_id):
        if str(record_id) == "999999":
            return None
        return {"id": record_id}

class FakeThreatQueryService:
    def get_recent_threats(self, page, page_size):
        return {"items": [], "total": 0}
    def get_threat_by_id(self, threat_id):
        if str(threat_id) == "999999":
            return None
        return {"id": threat_id}

@pytest.fixture
def app():
    deps = DependencyContainer()
    deps.model_service = FakeModelService()
    deps.device_query_service = FakeDeviceQueryService()
    deps.traffic_query_service = FakeTrafficQueryService()
    deps.threat_query_service = FakeThreatQueryService()
    # Dashboard services get initialized manually since we override the base ones
    from dashboard.services import DashboardModelService, DashboardDataService
    deps.dashboard_model_service = DashboardModelService(deps.model_service)
    deps.dashboard_data_service = DashboardDataService(
        deps.device_query_service,
        deps.traffic_query_service,
        deps.threat_query_service
    )

    app = create_app({"TESTING": True}, dependencies=deps)
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_models_overview_route(client):
    response = client.get('/dashboard/models')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "Model Overview" in content
    assert "Registered Models" in content or "No models are currently registered or active." in content

def test_devices_list_route(client):
    response = client.get('/dashboard/devices')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "Devices" in content

def test_devices_detail_route_not_found(client):
    response = client.get('/dashboard/devices/non_existent_id')
    assert response.status_code == 404

def test_traffic_list_route(client):
    response = client.get('/dashboard/traffic')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "Traffic" in content

def test_traffic_detail_route_not_found(client):
    response = client.get('/dashboard/traffic/999999')
    assert response.status_code == 404

def test_threats_list_route(client):
    response = client.get('/dashboard/threats')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "Threats" in content

def test_threats_detail_route_not_found(client):
    response = client.get('/dashboard/threats/999999')
    assert response.status_code == 404

def test_pagination_defaults_work(client):
    response = client.get('/dashboard/devices?page=abc&page_size=def')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "Page 1" in content
