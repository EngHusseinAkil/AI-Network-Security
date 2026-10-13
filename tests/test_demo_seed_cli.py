import json
from pathlib import Path
import re

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from ai.model_registry import ModelRegistry
from alerts.constants import AlertType
from backend.app_factory import create_app
from database.base import Base
from database.models import Alert, AuditLog, Device, ThreatLog, TrafficRecord
from database.seed import DEMO_ALERT_ID, DEMO_ALERT_TYPE
import database.connection as database_connection
import database.session as database_session


class TrackingSession(Session):
    close_count = 0

    def close(self):
        TrackingSession.close_count += 1
        super().close()


@pytest.fixture
def demo_app(tmp_path, monkeypatch):
    database_path = tmp_path / "demo.sqlite"
    engine = create_engine(f"sqlite:///{database_path}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    TrackingSession.close_count = 0
    factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        class_=TrackingSession,
    )
    monkeypatch.setattr(database_connection, "_engine", engine)
    monkeypatch.setattr(database_session, "_SessionFactory", factory)

    models_dir = tmp_path / "models"
    registry = ModelRegistry(str(models_dir / "registry.json"))
    registry.register_model("existing-1.0", str(models_dir / "existing"), {})
    registry.activate_model("existing-1.0")

    app = create_app({
        "TESTING": True,
        "ENVIRONMENT": "testing",
        "DEMO_MODE": True,
        "MODELS_DIR": models_dir,
        "SECRET_KEY": "demo-seed-test-secret",
    })
    yield app, factory, registry, engine
    engine.dispose()


def invoke_seed(app):
    return app.test_cli_runner().invoke(args=["demo", "seed"], input="y\n")


def test_seed_command_appears_in_demo_help(demo_app):
    app, _, _, _ = demo_app
    result = app.test_cli_runner().invoke(args=["demo", "--help"])
    assert result.exit_code == 0
    assert "seed" in result.output


def test_seed_command_refuses_production(demo_app):
    app, _, _, _ = demo_app
    app.config["ENVIRONMENT"] = "production"
    result = invoke_seed(app)
    assert result.exit_code != 0
    assert "unavailable in this environment" in result.output


def test_seed_command_creates_related_data_and_preserves_active_model(demo_app):
    app, factory, registry, _ = demo_app
    registry_before = json.loads(
        Path(registry.registry_file).read_text(encoding="utf-8")
    )

    result = invoke_seed(app)

    assert result.exit_code == 0, result.output
    assert TrackingSession.close_count == 1
    assert "WARNING: development-only" in result.output
    assert "environment: testing" in result.output
    assert "sqlite:///" in result.output
    assert "devices: created=2, updated=0, reused=0" in result.output
    assert "traffic_records: created=5, updated=0, reused=0" in result.output
    assert "threats: created=2, updated=0, reused=0" in result.output
    assert "alerts: created=1, updated=0, reused=0" in result.output
    assert DEMO_ALERT_ID in result.output

    with factory() as session:
        alert = session.scalar(select(Alert).where(Alert.public_alert_id == DEMO_ALERT_ID))
        assert alert is not None
        assert alert.alert_type == AlertType.SUSPECTED_PORT_SCAN.value
        assert AlertType(alert.alert_type) is AlertType.SUSPECTED_PORT_SCAN
        assert alert.threat_log_id is not None
        assert alert.threat_log.device_id is not None
        assert alert.threat_log.traffic_record_id is not None
        assert session.get(Device, alert.threat_log.device_id) is not None
        assert session.get(TrafficRecord, alert.threat_log.traffic_record_id) is not None
        assert session.get(ThreatLog, alert.threat_log_id) is not None

    registry_after = json.loads(
        Path(registry.registry_file).read_text(encoding="utf-8")
    )
    assert registry_after == registry_before
    assert registry.get_active_model_version() == "existing-1.0"


def test_second_seed_is_idempotent_without_duplicate_alerts(demo_app):
    app, factory, _, _ = demo_app
    assert invoke_seed(app).exit_code == 0

    second = invoke_seed(app)

    assert second.exit_code == 0, second.output
    assert "devices: created=0, updated=0, reused=2" in second.output
    assert "traffic_records: created=0, updated=0, reused=5" in second.output
    assert "threats: created=0, updated=0, reused=2" in second.output
    assert "alerts: created=0, updated=0, reused=1" in second.output
    with factory() as session:
        alerts = session.scalars(
            select(Alert).where(Alert.public_alert_id == DEMO_ALERT_ID)
        ).all()
        assert len(alerts) == 1


def test_seed_repairs_only_legacy_deterministic_alert(demo_app):
    app, factory, _, _ = demo_app
    assert invoke_seed(app).exit_code == 0
    with factory() as session:
        demo_alert = session.scalar(
            select(Alert).where(Alert.public_alert_id == DEMO_ALERT_ID)
        )
        demo_alert.alert_type = "intrusion"
        unrelated = Alert(
            public_alert_id="00000000-0000-4000-8000-000000000099",
            alert_type="intrusion",
            severity="low",
            status="new",
            title="Unrelated legacy record",
            description="Must not be changed by deterministic demo repair",
            source_category="test",
            confidence_score=0.5,
            risk_score=0.5,
            deduplication_key="unrelated-legacy-alert",
            created_at=demo_alert.created_at,
            updated_at=demo_alert.updated_at,
            safe_metadata={},
        )
        session.add(unrelated)
        session.commit()

    repair = invoke_seed(app)

    assert repair.exit_code == 0, repair.output
    assert "alerts: created=0, updated=1, reused=0" in repair.output
    with factory() as session:
        repaired = session.scalar(
            select(Alert).where(Alert.public_alert_id == DEMO_ALERT_ID)
        )
        untouched = session.scalar(
            select(Alert).where(
                Alert.public_alert_id == "00000000-0000-4000-8000-000000000099"
            )
        )
        assert repaired.alert_type == DEMO_ALERT_TYPE
        assert untouched.alert_type == "intrusion"

    second = invoke_seed(app)
    assert second.exit_code == 0, second.output
    assert "alerts: created=0, updated=0, reused=1" in second.output


def test_seed_rolls_back_and_closes_session_on_failure(demo_app, monkeypatch):
    app, factory, _, _ = demo_app

    def fail_alert_seed(_session, _threats):
        raise RuntimeError("forced seed failure")

    monkeypatch.setattr("database.seed.seed_sample_alerts", fail_alert_seed)
    result = invoke_seed(app)

    assert result.exit_code != 0
    assert "no records were committed" in result.output
    assert TrackingSession.close_count == 1
    with factory() as session:
        assert session.scalar(select(Device).limit(1)) is None
        assert session.scalar(select(TrafficRecord).limit(1)) is None
        assert session.scalar(select(ThreatLog).limit(1)) is None
        assert session.scalar(select(Alert).limit(1)) is None


def test_seeded_alert_is_visible_through_service_and_dashboard(demo_app):
    app, _, _, _ = demo_app
    assert invoke_seed(app).exit_code == 0

    service = app.extensions["dependencies"].alert_persistence_service
    alert = service.get_alert(DEMO_ALERT_ID)
    assert alert["public_alert_id"] == DEMO_ALERT_ID

    client = app.test_client()
    alerts_response = client.get("/dashboard/alerts")
    assert alerts_response.status_code == 200
    assert DEMO_ALERT_ID.encode() in alerts_response.data

    detail_response = client.get(f"/dashboard/alerts/{DEMO_ALERT_ID}")
    assert detail_response.status_code == 200
    assert b"Intrusion Detected" in detail_response.data


def authenticated_client(app):
    app.config["AUTHENTICATION_REQUIRED"] = True
    user = app.extensions["dependencies"].user_account_service.provision(
        "demo-operator",
        "demo-operator@example.test",
        "DemoLifecycle!123",
        "admin",
    )
    client = app.test_client()
    with client.session_transaction() as session:
        session["authenticated_user_id"] = user.public_user_id
    return client, user


def csrf_token(response):
    match = re.search(
        rb'name="csrf_token"\s+value="([^"]+)"',
        response.data,
    )
    assert match is not None
    return match.group(1).decode()


def test_seeded_alert_acknowledges_resolves_and_audits_actor(demo_app):
    app, factory, _, _ = demo_app
    assert invoke_seed(app).exit_code == 0
    client, actor = authenticated_client(app)

    detail = client.get(f"/dashboard/alerts/{DEMO_ALERT_ID}")
    assert detail.status_code == 200
    acknowledge = client.post(
        f"/dashboard/alerts/{DEMO_ALERT_ID}/acknowledge",
        data={
            "csrf_token": csrf_token(detail),
            "expected_version": "1",
        },
        follow_redirects=True,
    )
    assert acknowledge.status_code == 200
    assert b"Alert successfully acknowledged" in acknowledge.data
    assert b"Acknowledged" in acknowledge.data

    with factory() as session:
        acknowledged = session.scalar(
            select(Alert).where(Alert.public_alert_id == DEMO_ALERT_ID)
        )
        assert acknowledged.status == "acknowledged"
        assert acknowledged.acknowledged_at is not None
        acknowledge_audit = session.scalar(select(AuditLog).where(
            AuditLog.action == "dashboard.alert_acknowledge",
            AuditLog.entity_id == DEMO_ALERT_ID,
        ))
        assert acknowledge_audit is not None
        assert acknowledge_audit.outcome == "success"
        assert acknowledge_audit.occurred_at is not None
        assert acknowledge_audit.actor_public_user_id == actor.public_user_id

    confirmation = client.get(f"/dashboard/alerts/{DEMO_ALERT_ID}/resolve/confirm")
    assert confirmation.status_code == 200
    resolve_token = csrf_token(confirmation)
    resolve = client.post(
        f"/dashboard/alerts/{DEMO_ALERT_ID}/resolve",
        data={
            "csrf_token": resolve_token,
            "expected_version": "2",
            "confirm_action": "resolve",
        },
        follow_redirects=True,
    )
    assert resolve.status_code == 200
    assert b"Alert successfully resolved" in resolve.data

    with factory() as session:
        resolved = session.scalar(
            select(Alert).where(Alert.public_alert_id == DEMO_ALERT_ID)
        )
        assert resolved.status == "resolved"
        assert resolved.acknowledged_at is not None
        assert resolved.resolved_at is not None

    invalid = client.post(
        f"/dashboard/alerts/{DEMO_ALERT_ID}/acknowledge",
        data={
            "csrf_token": resolve_token,
            "expected_version": "3",
        },
    )
    assert invalid.status_code == 409
    assert b"Invalid transition" in invalid.data


def test_seeded_alert_can_be_dismissed_and_persists_timestamp(demo_app):
    app, factory, _, _ = demo_app
    assert invoke_seed(app).exit_code == 0
    client, _ = authenticated_client(app)

    confirmation = client.get(f"/dashboard/alerts/{DEMO_ALERT_ID}/dismiss/confirm")
    assert confirmation.status_code == 200
    dismissed = client.post(
        f"/dashboard/alerts/{DEMO_ALERT_ID}/dismiss",
        data={
            "csrf_token": csrf_token(confirmation),
            "expected_version": "1",
            "confirm_action": "dismiss",
        },
        follow_redirects=True,
    )
    assert dismissed.status_code == 200
    assert b"Alert successfully dismissed" in dismissed.data
    with factory() as session:
        alert = session.scalar(
            select(Alert).where(Alert.public_alert_id == DEMO_ALERT_ID)
        )
        assert alert.status == "dismissed"
        assert alert.dismissed_at is not None
