"""
Tests for Phase 6 – Milestone 6 (corrected):
  * Numeric form parsing (integer vs float field policy)
  * CSRF token lifecycle and session binding
  * Session cookie security configuration
  * API endpoint isolation (inference API routes unaffected)

Coverage matrix
---------------
Numeric parsing:
  [P] valid integer fields accept whole-number strings
  [P] valid float fields accept integer strings and fractional strings
  [P] fractional string rejected for integer field
  [P] scientific-notation string rejected for integer field
  [P] NaN rejected for float field
  [P] +Inf rejected for float field
  [P] -Inf rejected for float field
  [P] empty string rejected
  [P] whitespace-only string rejected
  [P] non-numeric string rejected
  [P] "3.7" is NOT silently truncated to 3 for integer fields
  [P] values are not rounded (e.g. "1.9" for integer field rejected, not rounded to 2)

CSRF:
  [P] GET /dashboard/inference does not require CSRF
  [P] CSRF token is stored in session after GET
  [P] valid same-session token succeeds on POST
  [P] missing submitted token fails (400)
  [P] empty submitted token fails (400)
  [P] mismatched token fails (400)
  [P] token from a *different* session fails (400)
  [P] missing session token fails (400)
  [P] token does not appear in log output

Session:
  [P] feature inputs are NOT stored in session after POST
  [P] SESSION_COOKIE_HTTPONLY is True
  [P] SESSION_COOKIE_SAMESITE is set

Inference success:
  [P] valid single-flow submission returns 200 with results
  [P] model unavailable returns 503
  [P] valid batch submission returns 200 with results
  [P] malformed batch JSON returns 400
  [P] batch with missing fields returns 400

API endpoints (must remain unaffected):
  [P] POST /api/v1/inference/flow still requires JSON content-type
  [P] POST /api/v1/inference/flow does NOT check CSRF (API client safety)
"""

import json
import html
import logging
import pytest

from backend.app_factory import create_app
from backend.dependencies import DependencyContainer
from backend.errors.exceptions import ServiceUnavailableError
from dashboard.security import CSRF_SESSION_KEY
from dashboard.form_parsing import (
    parse_float_field,
    parse_integer_field,
    parse_flow_form_fields,
    FLOAT_FIELDS,
    INTEGER_FIELDS,
)


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------

class FakeInferenceService:
    """Minimal fake that does not touch the filesystem or AI engine."""

    def __init__(self):
        self.fail_mode = False
        self.last_batch = None
        self.single_result = {
            "predicted_canonical_label": "benign",
            "predicted_encoded_class": 0,
            "confidence_score": 0.99,
            "risk_score": 0.01,
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
        self.last_batch = batch
        return self.batch_result


def _make_app(secret_key: str = "test-secret-key-for-pytest-only-do-not-ship"):
    """Build a test Flask application with injected fakes."""
    deps = DependencyContainer()
    fake_inference = FakeInferenceService()
    deps.inference_service = fake_inference

    from dashboard.services import DashboardInferenceService
    deps.dashboard_inference_service = DashboardInferenceService(fake_inference)

    app = create_app(
        config_override={
            "TESTING": True,
            "SECRET_KEY": secret_key,
            "WTF_CSRF_ENABLED": False,  # Only affects Flask-WTF if present; harmless.
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
def client(app):
    return app.test_client()


def _get_csrf_token_from_page(client) -> str:
    """GET the inference page and extract the CSRF token from the HTML."""
    resp = client.get("/dashboard/inference")
    assert resp.status_code == 200
    html = resp.data.decode()
    for line in html.split("\n"):
        if 'name="csrf_token"' in line:
            return line.split('value="')[1].split('"')[0]
    pytest.fail("CSRF token not found in inference page HTML")


def _valid_form(token: str, **overrides) -> dict:
    """Return a complete valid form payload."""
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


# ===========================================================================
# Unit tests: parse_float_field
# ===========================================================================

class TestParseFloatField:
    def test_valid_integer_string(self):
        assert parse_float_field("10", "duration") == 10.0

    def test_valid_float_string(self):
        assert parse_float_field("10.5", "duration") == 10.5

    def test_valid_negative_float(self):
        # Negative allowed here; schema range-checks happen downstream.
        assert parse_float_field("-1.5", "duration") == -1.5

    def test_nan_rejected(self):
        with pytest.raises(ValueError, match="NaN"):
            parse_float_field("nan", "duration")

    def test_nan_case_insensitive(self):
        with pytest.raises(ValueError, match="NaN"):
            parse_float_field("NaN", "duration")

    def test_positive_infinity_rejected(self):
        with pytest.raises(ValueError, match="Infinity"):
            parse_float_field("inf", "duration")

    def test_negative_infinity_rejected(self):
        with pytest.raises(ValueError, match="Infinity"):
            parse_float_field("-inf", "duration")

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError):
            parse_float_field("", "duration")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError):
            parse_float_field("   ", "duration")

    def test_non_numeric_rejected(self):
        with pytest.raises(ValueError):
            parse_float_field("abc", "duration")

    def test_scientific_notation_accepted_for_float(self):
        # e.g. "1e2" == 100.0 — float fields may accept scientific notation.
        result = parse_float_field("1e2", "duration")
        assert result == 100.0


# ===========================================================================
# Unit tests: parse_integer_field
# ===========================================================================

class TestParseIntegerField:
    def test_valid_integer(self):
        assert parse_integer_field("5", "packet_count") == 5

    def test_valid_zero(self):
        assert parse_integer_field("0", "packet_count") == 0

    def test_valid_large_integer(self):
        assert parse_integer_field("100000", "byte_count") == 100_000

    def test_fractional_rejected_15(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field("1.5", "packet_count")

    def test_fractional_rejected_22(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field("2.2", "packet_count")

    def test_fractional_rejected_trailing_dot(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field("5.", "packet_count")

    def test_fractional_rejected_leading_dot(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field(".5", "packet_count")

    def test_scientific_notation_rejected(self):
        # "3e-1" would be 0.3 — must be rejected even though it parses as float.
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field("3e-1", "packet_count")

    def test_scientific_notation_large_rejected(self):
        # "1e2" == 100 but we reject all scientific notation for integer fields.
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field("1e2", "packet_count")

    def test_37_not_silently_truncated(self):
        # "3.7" must NOT be accepted as 3.
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field("3.7", "packet_count")

    def test_19_not_silently_rounded(self):
        # "1.9" must NOT be rounded to 2.
        with pytest.raises(ValueError, match="whole integer"):
            parse_integer_field("1.9", "packet_count")

    def test_nan_rejected(self):
        with pytest.raises(ValueError):
            parse_integer_field("nan", "packet_count")

    def test_inf_rejected(self):
        with pytest.raises(ValueError):
            parse_integer_field("inf", "packet_count")

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError):
            parse_integer_field("", "packet_count")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError):
            parse_integer_field("   ", "packet_count")

    def test_alphabetic_rejected(self):
        with pytest.raises(ValueError):
            parse_integer_field("abc", "packet_count")

    def test_type_is_int(self):
        result = parse_integer_field("42", "packet_count")
        assert isinstance(result, int)
        assert not isinstance(result, bool)


# ===========================================================================
# Unit tests: parse_flow_form_fields
# ===========================================================================

class TestParseFlowFormFields:
    """Test the combined parser using a simple dict that mimics request.form."""

    def _form(self, **overrides):
        base = {
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
        # Remove keys whose value is None (simulate missing field)
        return {k: v for k, v in base.items() if v is not None}

    def test_valid_all_fields(self):
        result = parse_flow_form_fields(self._form())
        assert result["duration"] == 10.5
        assert isinstance(result["duration"], float)
        assert result["packet_count"] == 5
        assert isinstance(result["packet_count"], int)
        assert result["avg_packet_size"] == 60.0
        assert isinstance(result["avg_packet_size"], float)

    def test_integer_fields_return_int_type(self):
        result = parse_flow_form_fields(self._form())
        for field in INTEGER_FIELDS:
            assert isinstance(result[field], int), f"{field} should be int"
            assert not isinstance(result[field], bool)

    def test_float_fields_return_float_type(self):
        result = parse_flow_form_fields(self._form())
        for field in FLOAT_FIELDS:
            assert isinstance(result[field], float), f"{field} should be float"

    def test_fractional_packet_count_fails(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_flow_form_fields(self._form(packet_count="1.5"))

    def test_fractional_byte_count_fails(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_flow_form_fields(self._form(byte_count="2.2"))

    def test_fractional_protocol_enc_fails(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_flow_form_fields(self._form(protocol_enc="1.0"))

    def test_fractional_direction_enc_fails(self):
        with pytest.raises(ValueError, match="whole integer"):
            parse_flow_form_fields(self._form(direction_enc="3e-1"))

    def test_nan_duration_fails(self):
        with pytest.raises(ValueError, match="NaN"):
            parse_flow_form_fields(self._form(duration="nan"))

    def test_inf_avg_packet_size_fails(self):
        with pytest.raises(ValueError, match="Infinity"):
            parse_flow_form_fields(self._form(avg_packet_size="inf"))

    def test_missing_field_raises(self):
        with pytest.raises(ValueError, match="Missing required field: packet_count"):
            parse_flow_form_fields(self._form(packet_count=None))

    def test_empty_string_field_raises(self):
        with pytest.raises(ValueError):
            parse_flow_form_fields(self._form(duration=""))

    def test_whitespace_only_field_raises(self):
        with pytest.raises(ValueError):
            parse_flow_form_fields(self._form(duration="   "))

    def test_37_not_accepted_as_integer(self):
        with pytest.raises(ValueError):
            parse_flow_form_fields(self._form(packet_count="3.7"))

    def test_no_silent_coercion_for_integer_field(self):
        """Ensure "1.9" does not become int 2 or int 1 — it must be rejected."""
        with pytest.raises(ValueError):
            parse_flow_form_fields(self._form(min_packet_size="1.9"))


# ===========================================================================
# Integration tests: CSRF lifecycle
# ===========================================================================

class TestCSRFLifecycle:
    def test_get_does_not_require_csrf(self, client):
        """Safe GET requests must not be gated by CSRF."""
        resp = client.get("/dashboard/inference")
        assert resp.status_code == 200

    def test_csrf_token_stored_in_session(self, client):
        """After GET, the session must contain a CSRF token."""
        client.get("/dashboard/inference")
        with client.session_transaction() as sess:
            assert CSRF_SESSION_KEY in sess
            token = sess[CSRF_SESSION_KEY]
            assert token  # not empty
            assert len(token) == 64  # 32 bytes hex-encoded

    def test_valid_same_session_token_succeeds(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))
        # 200 on success, not 400 CSRF failure
        assert resp.status_code != 400 or b"CSRF" not in resp.data

    def test_missing_submitted_token_fails(self, client):
        client.get("/dashboard/inference")  # seed session
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(""),  # empty token
        )
        assert resp.status_code == 400
        assert b"Invalid or missing CSRF token" in resp.data

    def test_no_csrf_field_at_all_fails(self, client):
        """Form submitted with no csrf_token key whatsoever."""
        client.get("/dashboard/inference")
        form_data = {
            "duration": "10.5",
            "packet_count": "5",
            "byte_count": "500",
            "min_packet_size": "40",
            "max_packet_size": "100",
            "avg_packet_size": "60.0",
            "protocol_enc": "1",
            "direction_enc": "2",
        }
        resp = client.post("/dashboard/inference/flow", data=form_data)
        assert resp.status_code == 400
        assert b"Invalid or missing CSRF token" in resp.data

    def test_wrong_token_fails(self, client):
        """A syntactically valid but incorrect token must be rejected."""
        client.get("/dashboard/inference")
        with client.session_transaction() as sess:
            sess[CSRF_SESSION_KEY] = "aaaa" * 16  # 64 hex chars, wrong value

        wrong_token = "bbbb" * 16  # different 64-char token
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(wrong_token),
        )
        assert resp.status_code == 400
        assert b"Invalid or missing CSRF token" in resp.data

    def test_token_from_different_session_fails(self, app):
        """A token that was valid in session A must not pass in session B."""
        # Session A: obtain a token
        with app.test_client() as client_a:
            client_a.get("/dashboard/inference")
            with client_a.session_transaction() as sess_a:
                token_from_session_a = sess_a[CSRF_SESSION_KEY]

        # Session B: attempt to use session A's token
        with app.test_client() as client_b:
            client_b.get("/dashboard/inference")  # creates its own session
            resp = client_b.post(
                "/dashboard/inference/flow",
                data=_valid_form(token_from_session_a),
            )
            assert resp.status_code == 400
            assert b"Invalid or missing CSRF token" in resp.data

    def test_missing_session_token_fails(self, client):
        """If the session has no CSRF key at all, POST must fail."""
        # Do NOT call GET first — session is empty.
        with client.session_transaction() as sess:
            sess.clear()

        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form("any_token"),
        )
        assert resp.status_code == 400
        assert b"Invalid or missing CSRF token" in resp.data

    def test_csrf_token_not_in_log_output(self, client, caplog):
        """Ensure the token value never appears in log output on failure."""
        client.get("/dashboard/inference")
        with client.session_transaction() as sess:
            sess[CSRF_SESSION_KEY] = "secret_csrf_value_abc123"

        with caplog.at_level(logging.WARNING, logger="dashboard.security"):
            client.post(
                "/dashboard/inference/flow",
                data=_valid_form("wrong_token_xyz789"),
            )

        for record in caplog.records:
            assert "secret_csrf_value_abc123" not in record.getMessage(), (
                "Session CSRF token must never appear in log output."
            )
            assert "wrong_token_xyz789" not in record.getMessage(), (
                "Submitted CSRF token must never appear in log output."
            )


# ===========================================================================
# Session data isolation tests
# ===========================================================================

class TestSessionDataIsolation:
    def test_feature_inputs_not_stored_in_session(self, client):
        """Feature values must NOT be persisted in the session after POST."""
        token = _get_csrf_token_from_page(client)
        client.post("/dashboard/inference/flow", data=_valid_form(token))
        with client.session_transaction() as sess:
            # Only the CSRF key is permitted.
            session_keys = set(sess.keys())
            prohibited_keys = {
                "duration", "packet_count", "byte_count", "min_packet_size",
                "max_packet_size", "avg_packet_size", "protocol_enc",
                "direction_enc", "features", "result", "prediction",
            }
            leaked = session_keys & prohibited_keys
            assert not leaked, (
                f"Feature/result data leaked into session: {leaked}"
            )

    def test_prediction_result_not_stored_in_session(self, client):
        """Prediction results must NOT be persisted in the session."""
        token = _get_csrf_token_from_page(client)
        client.post("/dashboard/inference/flow", data=_valid_form(token))
        with client.session_transaction() as sess:
            assert "result" not in sess
            assert "prediction" not in sess
            assert "predicted_label" not in sess


# ===========================================================================
# Session cookie security configuration tests
# ===========================================================================

class TestSessionCookieSecurity:
    def test_httponly_is_true(self, app):
        assert app.config.get("SESSION_COOKIE_HTTPONLY") is True

    def test_samesite_is_set(self, app):
        samesite = app.config.get("SESSION_COOKIE_SAMESITE")
        assert samesite in ("Lax", "Strict"), (
            f"SESSION_COOKIE_SAMESITE must be 'Lax' or 'Strict', got {samesite!r}"
        )

    def test_secure_flag_is_false_in_testing(self, app):
        # TESTING=True means SESSION_COOKIE_SECURE should be False
        # so the test client (no TLS) works.
        assert app.config.get("SESSION_COOKIE_SECURE") is False

    def test_secret_key_is_set_from_config(self, app):
        """app.secret_key must equal the configured SECRET_KEY."""
        assert app.secret_key == app.config.get("SECRET_KEY")

    def test_secret_key_is_not_generated_per_import(self):
        """
        Two independently created apps with the same config must share the
        same secret key (derived from config, not generated at import time).
        """
        key = "stable-key-for-two-app-test-12345"
        app1, _ = _make_app(secret_key=key)
        app2, _ = _make_app(secret_key=key)
        assert app1.secret_key == app2.secret_key == key


# ===========================================================================
# Integration tests: inference form submissions
# ===========================================================================

class TestInferenceSubmission:
    def test_valid_single_flow_returns_200(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))
        assert resp.status_code == 200
        assert b"Single Flow Prediction Result" in resp.data
        assert b"benign" in resp.data

    def test_model_unavailable_returns_503(self, client, fake_svc):
        fake_svc.fail_mode = True
        token = _get_csrf_token_from_page(client)
        resp = client.post("/dashboard/inference/flow", data=_valid_form(token))
        assert resp.status_code == 503
        assert b"model_unavailable" in resp.data

    def test_fractional_integer_field_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(token, packet_count="1.5"),
        )
        assert resp.status_code == 400
        assert b"Single Flow Prediction Result" not in resp.data

    def test_scientific_notation_integer_field_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(token, direction_enc="3e-1"),
        )
        assert resp.status_code == 400

    def test_nan_duration_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(token, duration="nan"),
        )
        assert resp.status_code == 400

    def test_inf_avg_packet_size_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(token, avg_packet_size="inf"),
        )
        assert resp.status_code == 400

    def test_missing_field_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        form = _valid_form(token)
        del form["packet_count"]
        resp = client.post("/dashboard/inference/flow", data=form)
        assert resp.status_code == 400

    def test_empty_field_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(token, duration=""),
        )
        assert resp.status_code == 400

    def test_whitespace_field_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(token, byte_count="   "),
        )
        assert resp.status_code == 400

    def test_37_not_silently_coerced_to_3(self, client):
        token = _get_csrf_token_from_page(client)
        resp = client.post(
            "/dashboard/inference/flow",
            data=_valid_form(token, packet_count="3.7"),
        )
        assert resp.status_code == 400

    def test_valid_batch_flow_returns_200(self, client):
        token = _get_csrf_token_from_page(client)
        payload = {
            "flows": [{
                "duration": 10.0,
                "packet_count": 5,
                "byte_count": 500,
                "min_packet_size": 40,
                "max_packet_size": 100,
                "avg_packet_size": 60.0,
                "protocol_enc": 1,
                "direction_enc": 2,
            }]
        }
        resp = client.post(
            "/dashboard/inference/flows",
            data={"csrf_token": token, "batch_data": json.dumps(payload)},
        )
        assert resp.status_code == 200
        assert b"Batch Flow Prediction Results" in resp.data

    def test_two_valid_batch_rows_reach_service_without_wrapper(self, client, fake_svc):
        token = _get_csrf_token_from_page(client)
        flow = {
            "duration": 1.5,
            "packet_count": 10,
            "byte_count": 1500,
            "min_packet_size": 64,
            "max_packet_size": 150,
            "avg_packet_size": 150.0,
            "protocol_enc": 1,
            "direction_enc": 2,
        }
        payload = {
            "flows": [
                flow,
                {
                    **flow,
                    "duration": 10.0,
                    "packet_count": 10000,
                    "byte_count": 640000,
                    "max_packet_size": 64,
                    "avg_packet_size": 64.0,
                    "direction_enc": 3,
                },
            ]
        }

        resp = client.post(
            "/dashboard/inference/flows",
            data={"csrf_token": token, "batch_data": json.dumps(payload)},
        )

        assert resp.status_code == 200
        assert isinstance(fake_svc.last_batch, list)
        assert len(fake_svc.last_batch) == 2
        assert all(type(row) is dict for row in fake_svc.last_batch)
        assert "flows" not in fake_svc.last_batch[0]

    def test_malformed_batch_json_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        submitted = "{ invalid_json:"
        resp = client.post(
            "/dashboard/inference/flows",
            data={"csrf_token": token, "batch_data": submitted},
        )
        assert resp.status_code == 400
        assert b"Malformed JSON data" in resp.data
        assert submitted in html.unescape(resp.data.decode())

    def test_batch_missing_fields_returns_400(self, client):
        token = _get_csrf_token_from_page(client)
        payload = {"flows": [{"duration": 10.0}]}  # missing other fields
        resp = client.post(
            "/dashboard/inference/flows",
            data={"csrf_token": token, "batch_data": json.dumps(payload)},
        )
        assert resp.status_code == 400
        assert b"Batch Flow Prediction Results" not in resp.data
        assert json.dumps(payload) in html.unescape(resp.data.decode())

    def test_batch_inference_failure_preserves_submitted_json(self, client, fake_svc):
        token = _get_csrf_token_from_page(client)
        fake_svc.fail_mode = True
        payload = {
            "flows": [{
                "duration": 10.0,
                "packet_count": 5,
                "byte_count": 500,
                "min_packet_size": 40,
                "max_packet_size": 100,
                "avg_packet_size": 60.0,
                "protocol_enc": 1,
                "direction_enc": 2,
            }]
        }
        submitted = json.dumps(payload)

        resp = client.post(
            "/dashboard/inference/flows",
            data={"csrf_token": token, "batch_data": submitted},
        )

        assert resp.status_code == 503
        rendered = html.unescape(resp.data.decode())
        assert submitted in rendered
        assert 'id="batch_data"' in rendered
        assert "required" in rendered


# ===========================================================================
# API endpoint isolation tests
# ===========================================================================

class TestAPIEndpointIsolation:
    """
    The JSON inference API routes at /api/v1/inference/* must:
    * Require application/json content-type (unchanged).
    * NOT require a CSRF token (they are consumed by API clients, not browsers).
    * Continue to enforce JSON schema validation.
    """

    def test_api_flow_requires_json_content_type(self, client):
        """Posting form data to the API must still return 415."""
        resp = client.post(
            "/api/v1/inference/flow",
            data={"duration": "10"},
            content_type="application/x-www-form-urlencoded",
        )
        assert resp.status_code == 415

    def test_api_flow_does_not_require_csrf(self, client):
        """
        The API accepts well-formed JSON without a CSRF token.
        (Schema validation will return 400 for missing fields, not CSRF 400.)
        """
        payload = {
            "duration": 10.0,
            "packet_count": 5,
            "byte_count": 500,
            "min_packet_size": 40,
            "max_packet_size": 100,
            "avg_packet_size": 60.0,
            "protocol_enc": 1,
            "direction_enc": 2,
        }
        resp = client.post(
            "/api/v1/inference/flow",
            data=json.dumps(payload),
            content_type="application/json",
        )
        # 200 on success or 503 if the model is not loaded — either way, NOT 400 CSRF error.
        assert resp.status_code in (200, 503)
        if resp.status_code == 400:
            data = resp.get_json()
            assert data is not None, "API should always return JSON"
            assert "CSRF" not in str(data), "API must not fail on CSRF grounds"
