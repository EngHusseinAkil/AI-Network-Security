import re

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app_factory import create_app
from database.base import Base
from database.models.audit_log import AuditLog
import database.session as database_session


@pytest.fixture()
def auth_app(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(database_session, "_SessionFactory", factory)
    return create_app({
        "TESTING": True,
        "AUTHENTICATION_REQUIRED": True,
        "SECRET_KEY": "test-only-authentication-secret",
    })


def _csrf(client):
    with client.session_transaction() as state:
        return state["_csrf_token"]


def _create(app, role="viewer", login="alice"):
    return app.extensions["dependencies"].user_account_service.provision(
        login, f"{login}@example.test", "correct horse battery staple", role
    )


def _login(client, login="alice", next_path=""):
    client.get("/login")
    return client.post("/login", data={
        "csrf_token": _csrf(client),
        "login": login,
        "password": "correct horse battery staple",
        "next": next_path,
    })


def test_unauthenticated_dashboard_redirects_and_api_returns_json(auth_app):
    client = auth_app.test_client()
    response = client.get("/dashboard/")
    assert response.status_code == 303
    assert response.headers["Location"].startswith("/login?next=")
    api = client.get("/api/v1/monitoring/status")
    assert api.status_code == 401
    assert api.get_json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_login_is_csrf_protected_and_uses_generic_error(auth_app):
    client = auth_app.test_client()
    assert client.post("/login", data={}).status_code == 400
    client.get("/login")
    response = client.post("/login", data={
        "csrf_token": _csrf(client), "login": "missing", "password": "not valid"
    })
    assert response.status_code == 401
    assert b"Invalid login credentials." in response.data


def test_login_rotates_session_and_rejects_open_redirect(auth_app):
    _create(auth_app)
    client = auth_app.test_client()
    client.get("/login")
    old_csrf = _csrf(client)
    with client.session_transaction() as state:
        state["untrusted"] = "must disappear"
    response = client.post("/login", data={
        "csrf_token": old_csrf, "login": "alice",
        "password": "correct horse battery staple",
        "next": "https://attacker.example/",
    })
    assert response.status_code == 303
    assert response.headers["Location"] == "/dashboard/"
    with client.session_transaction() as state:
        assert "untrusted" not in state
        assert state["_csrf_token"] != old_csrf


def test_viewer_reads_but_server_denies_mutation(auth_app):
    _create(auth_app, "viewer")
    client = auth_app.test_client()
    _login(client)
    assert client.get("/dashboard/").status_code == 200
    assert client.get("/api/v1/monitoring/status").status_code == 200
    denied = client.post(
        "/dashboard/monitoring/flows/process",
        data={"csrf_token": _csrf(client)},
    )
    assert denied.status_code == 403


def test_viewer_cannot_stop_capture(auth_app):
    _create(auth_app, "viewer")
    client = auth_app.test_client()
    _login(client)
    denied = client.post(
        "/dashboard/monitoring/capture/stop",
        data={"csrf_token": _csrf(client)},
    )
    assert denied.status_code == 403


def test_successful_capture_stop_is_audited_as_success(auth_app):
    _create(auth_app, "operator")
    client = auth_app.test_client()
    _login(client)

    response = client.post(
        "/dashboard/monitoring/capture/stop",
        data={"csrf_token": _csrf(client)},
    )
    assert response.status_code == 303

    session = database_session.get_session()
    try:
        event = session.scalar(
            select(AuditLog)
            .where(AuditLog.action == "dashboard.capture_stop")
            .order_by(AuditLog.id.desc())
        )
        assert event is not None and event.outcome == "success"
    finally:
        session.close()


def test_role_and_active_status_are_reloaded_each_request(auth_app):
    user = _create(auth_app, "operator")
    client = auth_app.test_client()
    _login(client)
    assert client.post(
        "/dashboard/monitoring/flows/process",
        data={"csrf_token": _csrf(client)},
    ).status_code == 303
    auth_app.extensions["dependencies"].user_account_service.change_role(
        user.public_user_id, "viewer"
    )
    assert client.post(
        "/dashboard/monitoring/flows/process",
        data={"csrf_token": _csrf(client)},
    ).status_code == 403


def test_logout_is_post_only_csrf_protected_and_clears_session(auth_app):
    _create(auth_app)
    client = auth_app.test_client()
    _login(client)
    assert client.get("/logout").status_code == 405
    assert client.post("/logout", data={}).status_code == 400
    response = client.post("/logout", data={"csrf_token": _csrf(client)})
    assert response.status_code == 303
    assert client.get("/dashboard/").status_code == 303
