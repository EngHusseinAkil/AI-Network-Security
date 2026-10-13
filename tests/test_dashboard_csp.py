import re
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app_factory import create_app
from database.base import Base
import database.session as database_session


TEMPLATES = Path(__file__).resolve().parent.parent / "dashboard" / "templates"
EXPECTED_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self';"
)


@pytest.fixture()
def csp_app(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(database_session, "_SessionFactory", factory)
    return create_app({
        "TESTING": True,
        "AUTHENTICATION_REQUIRED": False,
        "SECRET_KEY": "test-only-csp-secret",
    })


def test_strict_csp_allows_same_origin_assets_without_inline_exceptions(csp_app):
    client = csp_app.test_client()
    for path in (
        "/login",
        "/dashboard/",
        "/dashboard/health",
        "/dashboard/monitoring",
        "/dashboard/alerts",
        "/dashboard/nonexistent",
    ):
        response = client.get(path)
        assert response.headers["Content-Security-Policy"] == EXPECTED_CSP
        assert response.headers["Cache-Control"] == "no-store, max-age=0"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Permissions-Policy"]

    policy = client.get("/dashboard/").headers["Content-Security-Policy"]
    assert "style-src 'self'" in policy
    assert "script-src 'self'" in policy
    assert "object-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "'unsafe-eval'" not in policy
    assert "'unsafe-inline'" not in policy


def test_dashboard_static_assets_are_same_origin_and_served(csp_app):
    client = csp_app.test_client()
    page = client.get("/dashboard/")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    css_url = "/dashboard/static/css/dashboard.css"
    js_url = "/dashboard/static/js/dashboard.js"
    assert f'href="{css_url}"' in html
    assert f'src="{js_url}"' in html
    assert client.get(css_url).status_code == 200
    assert client.get(js_url).status_code == 200


def test_dashboard_templates_have_no_csp_blocked_inline_code():
    for template in TEMPLATES.rglob("*.html"):
        source = template.read_text(encoding="utf-8")
        assert "style=" not in source, template
        assert "<style" not in source, template
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", source), template


def test_health_and_overview_render_only_linked_assets(csp_app):
    client = csp_app.test_client()
    for path in ("/dashboard/", "/dashboard/health"):
        response = client.get(path)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "style=" not in html
        assert "<style" not in html
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)
        assert 'href="/dashboard/static/css/dashboard.css"' in html
        assert 'src="/dashboard/static/js/dashboard.js"' in html


def test_authenticated_dashboard_pages_render_linked_assets(csp_app):
    csp_app.config["AUTHENTICATION_REQUIRED"] = True
    csp_app.extensions["dependencies"].user_account_service.provision(
        "csp-viewer",
        "csp-viewer@example.test",
        "correct horse battery staple",
        "viewer",
    )
    client = csp_app.test_client()
    client.get("/login")
    with client.session_transaction() as state:
        csrf_token = state["_csrf_token"]
    login = client.post("/login", data={
        "csrf_token": csrf_token,
        "login": "csp-viewer",
        "password": "correct horse battery staple",
    })
    assert login.status_code == 303

    for path in ("/dashboard/", "/dashboard/health", "/dashboard/alerts"):
        response = client.get(path)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'href="/dashboard/static/css/dashboard.css"' in html
        assert 'src="/dashboard/static/js/dashboard.js"' in html
