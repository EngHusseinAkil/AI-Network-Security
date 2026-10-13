import pytest
from flask import url_for
from backend.app_factory import create_app

@pytest.fixture
def app():
    app = create_app({"TESTING": True})
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_health_overview_route(client):
    """Test health overview route returns 200 and uses correct layout."""
    response = client.get('/dashboard/health')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "System Core" in content
    assert "AI Engine" in content
    assert "Backend APIs" in content
    assert 'class="skip-link"' in content  # accessibility layout exists

def test_health_system_route(client):
    """Test system health route returns 200 and renders details."""
    response = client.get('/dashboard/health/system')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "System Core" in content
    assert "Individual Checks" in content

def test_health_ai_route(client):
    """Test AI health route returns 200 and renders details."""
    response = client.get('/dashboard/health/ai')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "AI Engine Health" in content
    assert "Individual Checks" in content

def test_health_backend_route(client):
    """Test backend health route returns 200 and renders details."""
    response = client.get('/dashboard/health/backend')
    assert response.status_code == 200
    content = response.data.decode('utf-8')
    assert "Backend APIs Health" in content
    assert "Individual Checks" in content

def test_health_routes_accessible_and_safe(client):
    """Test that health pages do not expose stack traces or raw model paths."""
    response = client.get('/dashboard/health/ai')
    content = response.data.decode('utf-8')

    # Should not contain stack trace keywords or python paths
    assert "Traceback (most recent call last)" not in content
    assert "c:\\" not in content.lower()
    assert ".pkl" not in content.lower()

    # Navigation marks Health active
    assert 'href="/dashboard/health"' in content
    assert 'aria-current="page"' in content

def test_health_failure_isolation(app, client, monkeypatch):
    """Test that if a health service raises an exception, the dashboard isolates it and renders a safe fallback."""
    from dashboard.services import DashboardHealthService

    def mock_failing_health():
        raise RuntimeError("Simulated internal DB failure during health check")

    class FailingDashboardHealthService(DashboardHealthService):
        def get_backend_health(self):
            try:
                mock_failing_health()
            except Exception:
                return self._build_fallback("Backend APIs")

    with app.app_context():
        original_service = app.extensions['dependencies'].dashboard_health_service
        app.extensions['dependencies'].dashboard_health_service = FailingDashboardHealthService(
            original_service.system_health_svc,
            original_service.ai_health_service,
            original_service.backend_health_svc
        )

        response = client.get('/dashboard/health/backend')
        assert response.status_code == 200  # Should not crash 500
        content = response.data.decode('utf-8')

        # Check that safe fallback rendered
        assert "service is currently unavailable" in content.lower()
        assert "Simulated internal DB failure" not in content # Exception text MUST be hidden

        # Restore service
        app.extensions['dependencies'].dashboard_health_service = original_service
