import pytest
import time
import uuid
import secrets
import re
from flask import session
from unittest.mock import patch

from database.models.alert import Alert as PersistenceAlert
from database.session import session_scope

def _make_app(db_session):
    from backend.app_factory import create_app
    from backend.dependencies import DependencyContainer

    deps = DependencyContainer()

    # We must mock session_scope for alert persistence to use our db_session
    from contextlib import contextmanager
    @contextmanager
    def _mock_scope():
        try:
            yield db_session
            db_session.commit()
        except Exception:
            db_session.rollback()
            raise

    patcher = patch('backend.services.alert_persistence_service.session_scope', _mock_scope)
    patcher.start()

    class FakeInferenceService:
        def __init__(self):
            self.fail_mode = False
            self.single_result = {
                "predicted_canonical_label": "ddos",
                "predicted_encoded_class": 1,
                "confidence_score": 0.99,
                "risk_score": 0.98,
                "model_version": "v1.0",
                "schema_version": "v1.0"
            }
            self.batch_result = {
                "count": 1,
                "model_version": "v1.0",
                "inference_latency": {"average_seconds_per_row": 0.001},
                "predictions": [
                    {
                        "predicted_canonical_label": "benign",
                        "confidence_score": 0.99,
                        "risk_score": 0.01,
                    }
                ],
            }

        def predict_flow(self, features):
            res = self.single_result.copy()
            if float(features.get("duration", 100.0)) < 10.0:
                res["predicted_canonical_label"] = "benign"
                res["risk_score"] = 0.01
            return res

        def predict_flows(self, batch):
            return self.batch_result

    fake_inference = FakeInferenceService()
    deps.inference_service = fake_inference

    from dashboard.services import DashboardInferenceService
    deps.dashboard_inference_service = DashboardInferenceService(fake_inference)

    app = create_app(
        config_override={
            "TESTING": True,
            "SECRET_KEY": "test-key-alert-creation",
            "WTF_CSRF_ENABLED": False,
        },
        dependencies=deps,
    )

    # ensure patcher stops when app context tears down? It's easier to just yield app if it was a fixture generator, but wait!
    # I can just put the patch in a fixture.
    return app, patcher

@pytest.fixture()
def mock_app_and_client(db_session):
    app, patcher = _make_app(db_session)
    client = app.test_client()
    yield app, client
    patcher.stop()

@pytest.fixture()
def app(mock_app_and_client):
    return mock_app_and_client[0]

@pytest.fixture()
def client(mock_app_and_client):
    return mock_app_and_client[1]

def get_csrf_token(client):
    response = client.get('/dashboard/inference')
    match = re.search(r'<input type="hidden" name="csrf_token" value="([^"]+)">', response.data.decode())
    return match.group(1) if match else None

def get_recommendation_token(client, csrf_token, feature_value=85.0):
    response = client.post('/dashboard/inference/flow', data={
        "csrf_token": csrf_token,
        "duration": feature_value,
        "packet_count": "5",
        "byte_count": "500",
        "min_packet_size": "40",
        "max_packet_size": "100",
        "avg_packet_size": "60.0",
        "protocol_enc": "1",
        "direction_enc": "2"
    })
    match = re.search(r'name="recommendation_token"\s+value="([^"]+)"', response.data.decode())
    if not match:
        print("\nDEBUG:", response.data.decode())
    return match.group(1) if match else None

def test_eligible_recommendation_renders_form(client):
    csrf = get_csrf_token(client)
    token = get_recommendation_token(client, csrf, feature_value=95.0)
    assert token is not None

def test_benign_recommendation_renders_no_form(client):
    csrf = get_csrf_token(client)
    token = get_recommendation_token(client, csrf, feature_value=5.0) # Benign
    assert token is None

def test_batch_inference_renders_no_form(client):
    csrf = get_csrf_token(client)
    response = client.post('/dashboard/inference/flows', data={
        "csrf_token": csrf,
        "batch_data": '{"flows": [{"duration": 10.0, "packet_count": 5, "byte_count": 300, "min_packet_size": 40, "max_packet_size": 100, "avg_packet_size": 60.0, "protocol_enc": 1, "direction_enc": 2}]}'
    })
    match = re.search(r'<input type="hidden" name="recommendation_token" value="([^"]+)">', response.data.decode())
    assert match is None
    assert "Alert-policy evaluation is not available for batch inference" in response.data.decode()

def test_valid_creation_persists_one_alert(client, db_session):
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)

    response = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": rec_token
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Alert successfully created from policy recommendation" in response.data

    alerts = db_session.query(PersistenceAlert).all()
    assert len(alerts) == 1
    alert = alerts[0]

    # Assert server-generated and hardcoded fields
    assert alert.status == "new"
    assert alert.occurrence_count == 1
    assert alert.public_alert_id is not None
    assert "Detected" in alert.title
    assert "explicitly created" in alert.description
    assert alert.source_category == "manual_dashboard_inference"
    assert alert.risk_score > 0.8
    assert alert.alert_type == "suspected_ddos"

def test_valid_creation_returns_303(client, db_session):
    """Successful alert creation returns 303 See Other (POST→GET pattern)."""
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)

    resp = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": rec_token
    }, follow_redirects=False)
    assert resp.status_code == 303
    assert '/dashboard/alerts/' in resp.headers.get('Location', '')

def test_missing_csrf_fails(client):
    """POST without CSRF token is rejected with 400."""
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)

    response = client.post('/dashboard/alerts/from-recommendation', data={
        "recommendation_token": rec_token
    })
    assert response.status_code == 400

def test_invalid_csrf_fails(client):
    """POST with wrong CSRF token is rejected with 400."""
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)

    response = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": "invalid_csrf",
        "recommendation_token": rec_token
    })
    assert response.status_code == 400

def test_replay_creates_no_duplicate(client, db_session):
    """Sequential replay redirects to existing alert with warning; exactly one record persisted."""
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)

    # First submission: 303 See Other to the newly created alert detail
    resp1 = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": rec_token
    }, follow_redirects=False)
    assert resp1.status_code == 303  # POST→GET redirect

    # Sequential replay: 303 See Other to the *existing* alert detail
    resp2 = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": rec_token
    }, follow_redirects=False)
    assert resp2.status_code == 303  # redirect to existing alert

    # Following the replay redirect shows the fixed safe warning message
    resp2_follow = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": rec_token
    }, follow_redirects=True)
    assert b"This alert was already created." in resp2_follow.data

    # Exactly one alert persisted
    alerts = db_session.query(PersistenceAlert).all()
    assert len(alerts) == 1

def test_expired_token_fails(client, app):
    from dashboard.services import DashboardAlertCreationService
    csrf = get_csrf_token(client)

    import hashlib
    import time
    from itsdangerous import URLSafeTimedSerializer

    session_hash = hashlib.sha256(csrf.encode()).hexdigest()

    claims = {
        "predicted_canonical_label": "malicious",
        "confidence_score": 0.9,
        "risk_score": 0.9,
        "model_version": "v1",
        "schema_version": "v1",
        "proposed_alert_type": "suspected_ddos",
        "proposed_severity": "high",
        "reason_code": "high_risk",
        "policy_version": "1.0",
        "source_category": "manual_dashboard_inference",
        "occurrence_count": 1,
        "session_hash": session_hash,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time()),
        "purpose": "create_alert"
    }

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="alert-recommendation")

    with patch("time.time", return_value=time.time() - 400):
        expired_token = serializer.dumps(claims)

    response = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": expired_token
    }, follow_redirects=True)

    assert b"Could not create alert: The recommendation token has expired." in response.data

def test_modified_token_fails(client):
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)

    modified_token = rec_token[:-1] + ('A' if rec_token[-1] != 'A' else 'B')

    response = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": modified_token
    }, follow_redirects=True)

    assert b"Could not create alert: The recommendation token is invalid or corrupted." in response.data

def test_cross_session_token_fails(app):
    # Session 1
    client1 = app.test_client()
    csrf1 = get_csrf_token(client1)
    rec_token = get_recommendation_token(client1, csrf1, feature_value=95.0)

    # Session 2
    client2 = app.test_client()
    csrf2 = get_csrf_token(client2)

    response = client2.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf2,
        "recommendation_token": rec_token
    }, follow_redirects=True)

    assert b"Could not create alert: Token session binding failed. Cross-session request rejected." in response.data

def test_wrong_purpose_token_fails(client, app):
    csrf = get_csrf_token(client)
    import hashlib
    from itsdangerous import URLSafeTimedSerializer

    session_hash = hashlib.sha256(csrf.encode()).hexdigest()
    claims = {
        "predicted_canonical_label": "malicious",
        "proposed_alert_type": "suspected_ddos",
        "proposed_severity": "high",
        "session_hash": session_hash,
        "nonce": secrets.token_hex(16),
        "purpose": "wrong_purpose" # WRONG PURPOSE
    }

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="alert-recommendation")
    bad_token = serializer.dumps(claims)

    response = client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": bad_token
    }, follow_redirects=True)

    assert b"Could not create alert: Invalid token purpose." in response.data

def test_no_threat_log_written(client, db_session):
    from database.models import ThreatLog
    initial_threats = db_session.query(ThreatLog).count()

    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)

    client.post('/dashboard/alerts/from-recommendation', data={
        "csrf_token": csrf,
        "recommendation_token": rec_token
    })

    final_threats = db_session.query(ThreatLog).count()
    assert initial_threats == final_threats


def test_concurrent_conflict_returns_409(client, db_session):
    from utils.exceptions import ConflictError
    from unittest.mock import patch
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)
    with patch(
        'dashboard.services.DashboardAlertCreationService.create_alert_from_token',
        side_effect=ConflictError('Concurrent duplicate', details={})
    ):
        response = client.post('/dashboard/alerts/from-recommendation', data={
            'csrf_token': csrf, 'recommendation_token': rec_token
        }, follow_redirects=False)
    assert response.status_code == 409
    assert db_session.query(PersistenceAlert).count() == 0


def test_get_after_redirect_creates_nothing(client, db_session):
    csrf = get_csrf_token(client)
    rec_token = get_recommendation_token(client, csrf, feature_value=95.0)
    resp = client.post('/dashboard/alerts/from-recommendation', data={
        'csrf_token': csrf, 'recommendation_token': rec_token
    }, follow_redirects=False)
    assert resp.status_code == 303
    location = resp.headers['Location']
    assert db_session.query(PersistenceAlert).count() == 1
    get_resp = client.get(location)
    assert get_resp.status_code == 200
    assert db_session.query(PersistenceAlert).count() == 1
