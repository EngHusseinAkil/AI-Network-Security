import pytest
from datetime import timedelta
import json

from alerts.models import Alert as DomainAlert
from alerts.constants import AlertType, AlertSeverity, AlertStatus
from utils.time_utils import get_current_utc_time

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from unittest.mock import patch, MagicMock

@pytest.fixture
def mock_session_scope(db_session):
    from contextlib import contextmanager
    @contextmanager
    def _mock_scope():
        try:
            yield db_session
            db_session.commit()
        except Exception:
            db_session.rollback()
            raise

    with patch('backend.services.alert_persistence_service.session_scope', _mock_scope):
        yield db_session

@pytest.fixture
def app(mock_session_scope):
    deps = DependencyContainer()
    app = create_app(dependencies=deps)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def seeded_alerts(app, db_session):
    deps = app.extensions['dependencies']
    service = deps.alert_persistence_service
    now = get_current_utc_time()

    # Store some alerts
    for i in range(5):
        domain_alert = DomainAlert(
            alert_id=f"api-pub-{i}",
            type=AlertType.SUSPECTED_DDOS if i % 2 == 0 else AlertType.SUSPECTED_PORT_SCAN,
            severity=AlertSeverity.HIGH if i < 3 else AlertSeverity.LOW,
            status=AlertStatus.NEW,
            title=f"Alert {i}",
            description="Test description",
            source_category="network",
            predicted_canonical_label="test",
            confidence_score=0.9,
            risk_score=0.9,
            model_version="v1",
            schema_version="1",
            created_at=now + timedelta(seconds=i),
            deduplication_key=f"api-dedup-{i}",
            safe_metadata={"key": "value"}
        )
        service.store_alert(domain_alert, "v1", "TEST")

    return 5

def test_list_alerts_api(client, seeded_alerts):
    response = client.get('/api/v1/alerts/')
    assert response.status_code == 200

    data = response.json
    assert data['success'] is True
    assert len(data['data']) == 5
    assert data['metadata']['total_items'] == 5

    # Check that deduplication_key and internal id are not exposed
    first_alert = data['data'][0]
    assert 'deduplication_key' not in first_alert
    assert 'id' not in first_alert
    assert 'public_alert_id' in first_alert

def test_list_alerts_pagination(client, seeded_alerts):
    response = client.get('/api/v1/alerts/?page=1&page_size=2')
    assert response.status_code == 200

    data = response.json
    assert len(data['data']) == 2
    assert data['metadata']['page'] == 1
    assert data['metadata']['page_size'] == 2

def test_list_alerts_filtering(client, seeded_alerts):
    response = client.get('/api/v1/alerts/?severity=high')
    assert response.status_code == 200

    data = response.json
    assert len(data['data']) == 3
    assert data['metadata']['filters']['severity'] == 'high'

def test_invalid_filtering(client):
    response = client.get('/api/v1/alerts/?severity=invalid_severity')
    assert response.status_code == 400
    assert response.json['error']['code'] == 'VALIDATION_ERROR'

def test_invalid_pagination(client):
    response = client.get('/api/v1/alerts/?page=-1')
    assert response.status_code == 400

    response = client.get('/api/v1/alerts/?page_size=999999')
    assert response.status_code == 400

def test_get_alert_detail(client, seeded_alerts):
    response = client.get('/api/v1/alerts/api-pub-0')
    assert response.status_code == 200

    data = response.json['data']
    assert data['public_alert_id'] == 'api-pub-0'
    assert data['description'] == 'Test description'
    assert data['safe_metadata'] == {'key': 'value'}
    assert 'deduplication_key' not in data
    assert 'id' not in data

def test_get_alert_not_found(client):
    response = client.get('/api/v1/alerts/nonexistent-id')
    assert response.status_code == 404
    assert response.json['error']['code'] == 'NOT_FOUND'
