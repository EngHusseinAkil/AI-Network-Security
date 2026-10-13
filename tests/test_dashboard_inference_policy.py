"""
Tests for Phase 6 - Milestone 11: Inference-to-Alert Policy Evaluation
"""

import json
import pytest

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.errors.exceptions import ServiceUnavailableError
from dashboard.security import CSRF_SESSION_KEY

class FakeInferenceService:
    def __init__(self):
        self.fail_mode = False
        self.single_result = {
            "predicted_canonical_label": "malware",
            "predicted_encoded_class": 1,
            "confidence_score": 0.99,
            "risk_score": 0.98,
            "model_version": "v1.0",
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
        if self.fail_mode:
            raise ServiceUnavailableError("model_unavailable: Engine down")
        return self.single_result

    def predict_flows(self, batch):
        if self.fail_mode:
            raise ServiceUnavailableError("model_unavailable: Engine down")
        return self.batch_result

def _make_app():
    deps = DependencyContainer()
    fake_inference = FakeInferenceService()
    deps.inference_service = fake_inference

    from dashboard.services import DashboardInferenceService, DashboardAlertEvaluationService
    deps.dashboard_inference_service = DashboardInferenceService(fake_inference)

    # Let dependencies.py set up the policy and evaluation service automatically
    # Or explicitly override for isolation
    app = create_app(
        config_override={
            "TESTING": True,
            "SECRET_KEY": "test-key-policy",
            "WTF_CSRF_ENABLED": False,
        },
        dependencies=deps,
    )
    return app, fake_inference

@pytest.fixture()
def app():
    a, _ = _make_app()
    return a

@pytest.fixture()
def fake_svc(app):
    return app.extensions["dependencies"].inference_service

@pytest.fixture()
def eval_svc(app):
    return app.extensions["dependencies"].dashboard_alert_evaluation_service

@pytest.fixture()
def client(app):
    return app.test_client()

def _get_csrf_token(client):
    resp = client.get("/dashboard/inference")
    html = resp.data.decode()
    for line in html.split("\n"):
        if 'name="csrf_token"' in line:
            return line.split('value="')[1].split('"')[0]
    return ""

def _valid_form(token, **overrides):
    base = {
        "csrf_token": token,
        "duration": "10.5",
        "packet_count": "5",
        "byte_count": "500",
        "min_packet_size": "40",
        "max_packet_size": "100",
        "avg_packet_size": "60.0",
        "protocol_enc": "1",
        "direction_enc": "2",
    }
    base.update(overrides)
    return base

class TestInferencePolicyEvaluation:

    def test_benign_prediction_no_alert(self, client, fake_svc):
        # 1. benign result produces no recommendation
        fake_svc.single_result["predicted_canonical_label"] = "benign"
        fake_svc.single_result["risk_score"] = 0.99  # even high risk doesn't override benign

        token = _get_csrf_token(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))

        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Alert Policy Recommendation" in data
        assert "No Alert Required" in data
        assert "benign_prediction" in data

    def test_qualifying_threat_recommends_alert(self, client, fake_svc):
        # 2. qualifying threat produces a recommendation
        fake_svc.single_result["predicted_canonical_label"] = "ddos"
        fake_svc.single_result["risk_score"] = 0.96  # critical
        fake_svc.single_result["confidence_score"] = 0.99

        token = _get_csrf_token(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))

        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Create Alert" in data
        assert "suspected_ddos" in data
        assert "critical" in data.lower()  # It displays Critical

    def test_unknown_label_uncertainty_policy(self, client, fake_svc):
        # 3. unknown follows uncertainty policy
        fake_svc.single_result["predicted_canonical_label"] = "unknown"
        fake_svc.single_result["risk_score"] = 0.85
        fake_svc.single_result["confidence_score"] = 0.80

        token = _get_csrf_token(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))

        assert resp.status_code == 200
        data = resp.data.decode()
        assert "suspicious_unknown" in data
        assert "unknown_uncertainty" in data

    def test_risk_alone_does_not_always_create_critical(self, client, fake_svc):
        # 4. risk alone does not always create critical severity (e.g. unknown maxes at Medium)
        fake_svc.single_result["predicted_canonical_label"] = "unknown"
        fake_svc.single_result["risk_score"] = 0.99  # very high

        token = _get_csrf_token(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))

        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Medium" in data
        assert "Critical" not in data

    def test_batch_inference_deferred(self, client):
        # 5. batch inference displays the deferred-evaluation notice
        token = _get_csrf_token(client)
        payload = {"flows": [{"duration": 10.0, "packet_count": 5, "byte_count": 500, "min_packet_size": 40, "max_packet_size": 100, "avg_packet_size": 60.0, "protocol_enc": 1, "direction_enc": 2}]}
        resp = client.post(
            "/dashboard/inference/flows",
            data={"csrf_token": token, "batch_data": json.dumps(payload)},
        )
        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Batch Flow Prediction Results" in data
        assert "Alert-policy evaluation is not available for batch inference in this milestone." in data
        assert "Create Alert" not in data

    def test_policy_failure_preserves_prediction(self, client, eval_svc, monkeypatch):
        # 6. successful prediction still renders when policy fails
        # 7. policy-unavailable notice is safe
        def mock_evaluate(*args, **kwargs):
            raise ValueError("Intentional simulated policy crash")

        monkeypatch.setattr(eval_svc, "evaluate_single_inference", mock_evaluate)

        token = _get_csrf_token(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))

        # Must not 500
        assert resp.status_code == 200
        data = resp.data.decode()
        assert "Single Flow Prediction Result" in data  # Prediction rendered
        assert "Policy evaluation unavailable" in data
        assert "Intentional simulated policy crash" not in data  # No raw exception

    def test_invalid_inference_does_not_call_policy(self, client, eval_svc, monkeypatch):
        # 8. invalid inference does not call policy
        called = False
        def mock_evaluate(*args, **kwargs):
            nonlocal called
            called = True
            return {}
        monkeypatch.setattr(eval_svc, "evaluate_single_inference", mock_evaluate)

        token = _get_csrf_token(client)
        # fractional integer
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token, packet_count="1.5"))

        assert resp.status_code == 400
        assert not called

    def test_inference_failure_does_not_call_policy(self, client, fake_svc, eval_svc, monkeypatch):
        # 9. inference failure does not call policy
        fake_svc.fail_mode = True

        called = False
        def mock_evaluate(*args, **kwargs):
            nonlocal called
            called = True
            return {}
        monkeypatch.setattr(eval_svc, "evaluate_single_inference", mock_evaluate)

        token = _get_csrf_token(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))

        assert resp.status_code == 503
        assert not called

    def test_safety_and_privacy(self, client):
        # 10. page explicitly states no alert was created
        token = _get_csrf_token(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))
        assert resp.status_code == 200
        data = resp.data.decode()
        assert "No alert was created, no alert was persisted, no notification was sent, and no traffic or device was blocked" in data
        # Check that cooldown is not falsely claimed
        assert "not_evaluated" in data

    def test_cooldown_and_suppression_not_claimed(self, eval_svc, fake_svc):
        # Verify internal mapping directly on the service
        rec = eval_svc.evaluate_single_inference(fake_svc.single_result)
        assert rec["cooldown_status"] == "not_evaluated"
        assert rec["available"] is True
