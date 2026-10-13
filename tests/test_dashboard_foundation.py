"""
Tests for Phase 6 Dashboard Foundation.
"""
import pytest
from flask import Flask

from backend.app_factory import create_app

@pytest.fixture
def app():
    app = create_app({"TESTING": True})
    # For dashboard 404 test to bypass central API error handlers,
    # we need the app to process a dashboard route.
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_dashboard_blueprint_registered(app: Flask):
    """Test that the dashboard blueprint is registered correctly."""
    assert 'dashboard' in app.blueprints

def test_dashboard_index_route(client):
    """Test that the dashboard index route returns 200 and renders safe HTML."""
    response = client.get('/dashboard/')
    assert response.status_code == 200

    # Decode content
    content = response.data.decode('utf-8')

    # Check safe static info
    assert "Dashboard Foundation" in content
    # The monitoring feature is now live; the old "not enabled yet" banner has
    # been removed.  Verify the Monitoring nav link is present instead.
    assert "Monitoring" in content

    # Check secure headers are present
    assert 'X-Frame-Options' in response.headers

    # Verify no API error envelope is used for HTML routes
    assert '"success": false' not in content

def test_api_behavior_unchanged(client):
    """Test that the API still returns JSON error envelopes."""
    response = client.get('/api/v1/nonexistent')
    # Should be 404, but API returns JSON envelope
    assert response.status_code == 404
    assert response.content_type == 'application/json'
    json_data = response.get_json()
    assert json_data['success'] is False
    assert 'error' in json_data

def test_dashboard_404_behavior(client):
    """Test that dashboard 404 behavior is safe HTML (or standard Flask 404), not API JSON."""
    response = client.get('/dashboard/nonexistent')
    assert response.status_code == 404

    if response.is_json:
        json_data = response.get_json()
        assert not ('success' in json_data and json_data['success'] is False), "Dashboard 404 should not return API JSON envelope."

def test_dashboard_accessibility_and_layout(client):
    """Test semantic HTML, landmarks, and a11y features."""
    response = client.get('/dashboard/')
    content = response.data.decode('utf-8')

    # Check skip link
    assert 'class="skip-link"' in content
    assert 'href="#main-content"' in content

    # Check landmarks
    assert 'role="banner"' in content or '<header' in content
    assert 'role="main"' in content or '<main' in content
    assert 'role="contentinfo"' in content or '<footer' in content

    # Check aria-current for active navigation
    assert 'aria-current="page"' in content
    assert 'class="nav-link active"' in content

def test_dashboard_components_render(client):
    """Test that reusable components render without real data."""
    response = client.get('/dashboard/')
    content = response.data.decode('utf-8')

    # Info card and empty state should be rendered
    assert 'class="card"' in content
    assert 'class="empty-state"' in content
    assert 'Monitoring and data fetching are not enabled yet.' in content
