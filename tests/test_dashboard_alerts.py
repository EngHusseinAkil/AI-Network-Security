import pytest
import json
import re
from unittest.mock import patch, MagicMock

from alerts.models import Alert as DomainAlert
from alerts.constants import AlertType, AlertSeverity, AlertStatus
from dashboard.security import CSRF_SESSION_KEY
from utils.time_utils import get_current_utc_time
from datetime import timedelta
from database.models.alert import Alert as PersistenceAlert
from database.session import session_scope

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer

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

    with patch('tests.test_dashboard_alerts.session_scope', _mock_scope):
        with patch('backend.services.alert_persistence_service.session_scope', _mock_scope):
            yield db_session

@pytest.fixture()
def app(mock_session_scope):
    deps = DependencyContainer()
    app = create_app(
        config_override={"TESTING": True, "SECRET_KEY": "test-key"},
        dependencies=deps,
    )
    return app

@pytest.fixture()
def client(app):
    return app.test_client()

def _get_csrf_token_from_page(client, url) -> str:
    """GET the page and extract the CSRF token from the HTML."""
    resp = client.get(url)
    assert resp.status_code == 200
    html = resp.data.decode()
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not match:
        pytest.fail("CSRF token not found in page HTML")
    return match.group(1)

@pytest.fixture
def mock_alerts_in_db(app, mock_session_scope):
    """Seed the database with test alerts."""
    now = get_current_utc_time()
    alerts = []

    # Use db_session directly from mock_session_scope which yields db_session
    session = mock_session_scope
    for i in range(5):
        a = PersistenceAlert(
            public_alert_id=f"dash-alert-{i}",
            alert_type="suspected_ddos",
            severity="high",
            status="new" if i != 2 else "acknowledged",
            title=f"Alert {i}",
            description="Test",
            source_category="network",
            confidence_score=0.9,
            risk_score=0.9,
            deduplication_key=f"dash-dedup-{i}",
            occurrence_count=1,
            version=1,
            created_at=now,
            safe_metadata={}
        )
        if i == 2:
            a.acknowledged_at = now
        session.add(a)
        alerts.append(a.public_alert_id)
    session.commit()
    return alerts

class TestDashboardAlerts:
    def test_alerts_list_page(self, client, mock_alerts_in_db):
        resp = client.get('/dashboard/alerts')
        assert resp.status_code == 200
        data = resp.data.decode()
        assert "dash-alert-0" in data
        assert "dash-alert-1" in data

    def test_alert_detail_page(self, client, mock_alerts_in_db):
        resp = client.get(f'/dashboard/alerts/{mock_alerts_in_db[0]}')
        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Acknowledge Alert" in data

    def test_alert_missing_returns_404(self, client):
        resp = client.get('/dashboard/alerts/nonexistent-alert')
        assert resp.status_code == 404

class TestDashboardAlertsLifecycle:
    def test_acknowledge_alert_success(self, client, mock_alerts_in_db):
        alert_id = mock_alerts_in_db[0]
        token = _get_csrf_token_from_page(client, f'/dashboard/alerts/{alert_id}')

        resp = client.post(f'/dashboard/alerts/{alert_id}/acknowledge', data={
            "csrf_token": token,
            "expected_version": "1"
        }, follow_redirects=True)

        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Alert successfully acknowledged" in data

        # Verify it has no Acknowledge button anymore
        assert "Acknowledge Alert" not in data

    def test_resolve_alert_success(self, client, mock_alerts_in_db):
        alert_id = mock_alerts_in_db[1]

        # 1. GET confirm page
        resp = client.get(f'/dashboard/alerts/{alert_id}/resolve/confirm')
        assert resp.status_code == 200
        html = resp.data.decode()
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        if not match:
            pytest.fail("CSRF token not found in confirm page")
        token = match.group(1)

        # 2. POST with confirmation
        resp = client.post(f'/dashboard/alerts/{alert_id}/resolve', data={
            "csrf_token": token,
            "expected_version": "1",
            "confirm_action": "resolve"
        }, follow_redirects=True)
        if resp.status_code != 200:
            print("RESOLVE TEST RESPONSE:", resp.data.decode())
        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Alert successfully resolved" in data
        # No lifecycle buttons should exist on resolved alert
        assert "Acknowledge Alert" not in data
        assert "Resolve Alert" not in data

    def test_stale_update_returns_409(self, client, mock_alerts_in_db):
        alert_id = mock_alerts_in_db[0]
        token = _get_csrf_token_from_page(client, f'/dashboard/alerts/{alert_id}')

        # We try to acknowledge with wrong version
        resp = client.post(f'/dashboard/alerts/{alert_id}/acknowledge', data={
            "csrf_token": token,
            "expected_version": "99"
        }, follow_redirects=True)

        assert resp.status_code == 409
        assert b"modified" in resp.data

    def test_terminal_confirmation_required(self, client, mock_alerts_in_db):
        alert_id = mock_alerts_in_db[1]
        token = _get_csrf_token_from_page(client, f'/dashboard/alerts/{alert_id}')

        # Missing confirm_action
        resp = client.post(f'/dashboard/alerts/{alert_id}/resolve', data={
            "csrf_token": token,
            "expected_version": "1"
        })

        assert resp.status_code == 400
        assert b"Explicit confirmation required" in resp.data

    def test_repeated_action_returns_409(self, client, mock_alerts_in_db):
        # Get token from a new alert's page
        token = _get_csrf_token_from_page(client, f'/dashboard/alerts/{mock_alerts_in_db[0]}')

        # mock_alerts_in_db[2] is already acknowledged
        alert_id = mock_alerts_in_db[2]

        resp = client.post(f'/dashboard/alerts/{alert_id}/acknowledge', data={
            "csrf_token": token,
            "expected_version": "1"
        }, follow_redirects=True)

        assert resp.status_code == 409
        assert b"Invalid transition" in resp.data

    def test_missing_csrf_returns_400(self, client, mock_alerts_in_db):
        alert_id = mock_alerts_in_db[0]
        resp = client.post(f'/dashboard/alerts/{alert_id}/acknowledge', data={
            "expected_version": "1"
        })
        assert resp.status_code == 400
        assert b"Invalid or missing CSRF token" in resp.data
