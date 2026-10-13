"""Signed live-flow recommendation tokens and explicit idempotent alert creation."""
from datetime import datetime, timezone
import hashlib
import logging
import secrets
import uuid

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from alerts.constants import AlertSeverity, AlertStatus, AlertType
from alerts.models import Alert
from utils.exceptions import ConflictError

TOKEN_PURPOSE = "live-flow-alert-recommendation-v1"
TOKEN_SALT = "live-flow-alert-recommendation"
TOKEN_MAX_AGE = 300
logger = logging.getLogger(__name__)


class LiveFlowAlertError(Exception):
    status_code = 400


class LiveFlowAlertForbidden(LiveFlowAlertError):
    status_code = 403


class LiveFlowAlertNotFound(LiveFlowAlertError):
    status_code = 404


class LiveFlowAlertConflict(LiveFlowAlertError):
    status_code = 409


class LiveFlowAlertCreationService:
    def __init__(self, secret_key, state_service, persistence_service, schema_version,
                 utc_clock=None):
        self._serializer = URLSafeTimedSerializer(secret_key, salt=TOKEN_SALT)
        self._state = state_service
        self._persistence = persistence_service
        self._schema_version = schema_version
        self._utc = utc_clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def eligible(record):
        return bool(
            record
            and record.feature_compatible
            and record.inference_status == "success"
            and record.policy_status == "success"
            and record.alert_recommended
            and record.proposed_alert_type
            and record.proposed_severity
            and record.reason_code
            and record.source_category == "live_metadata_flow"
            and not record.alert_persisted
        )

    def generate_token(self, evaluation_id, session_csrf):
        record = self._state.get_record(evaluation_id)
        if not self.eligible(record) or record.evaluation_schema_version != self._schema_version:
            return None
        return self._serializer.dumps({
            "evaluation_id": record.evaluation_id,
            "evaluation_schema_version": record.evaluation_schema_version,
            "flow_id": record.flow_id,
            "model_version": record.model_version,
            "policy_version": record.policy_version,
            "purpose": TOKEN_PURPOSE,
            "session_digest": hashlib.sha256(session_csrf.encode()).hexdigest(),
        })

    def create_alert(self, evaluation_id, token, session_csrf):
        from utils.signed_tokens import is_canonical_signed_token
        if not is_canonical_signed_token(token):
            raise LiveFlowAlertError("Invalid or expired recommendation token")
        try:
            claims = self._serializer.loads(token, max_age=TOKEN_MAX_AGE)
        except (SignatureExpired, BadSignature) as exc:
            raise LiveFlowAlertError("Invalid or expired recommendation token") from exc
        if claims.get("purpose") != TOKEN_PURPOSE:
            raise LiveFlowAlertError("Invalid recommendation token purpose")
        if claims.get("evaluation_id") != evaluation_id:
            raise LiveFlowAlertError("Recommendation token does not match evaluation")
        expected = hashlib.sha256(session_csrf.encode()).hexdigest()
        if not secrets.compare_digest(claims.get("session_digest", ""), expected):
            raise LiveFlowAlertForbidden("Recommendation token session mismatch")
        record = self._state.get_record(evaluation_id)
        if record is None:
            raise LiveFlowAlertNotFound("Evaluation not found")
        expected_claims = {
            "evaluation_schema_version": record.evaluation_schema_version,
            "flow_id": record.flow_id,
            "model_version": record.model_version,
            "policy_version": record.policy_version,
        }
        if any(claims.get(key) != value for key, value in expected_claims.items()):
            raise LiveFlowAlertError("Recommendation token no longer matches evaluation")
        origin = self._origin_key(record)
        existing = self._persistence.find_by_deduplication_key(origin)
        if existing:
            self._state.mark_alert_persisted(
                evaluation_id, existing["public_alert_id"], self._utc()
            )
            logger.info(
                "Live-flow alert request evaluation_id=%s alert_id=%s replay=true",
                evaluation_id, existing["public_alert_id"],
            )
            return existing["public_alert_id"], True
        if not self.eligible(record) or record.evaluation_schema_version != self._schema_version:
            raise LiveFlowAlertConflict("Evaluation is not eligible for alert creation")
        try:
            alert_type = AlertType(record.proposed_alert_type)
            severity = AlertSeverity(record.proposed_severity)
        except ValueError as exc:
            raise LiveFlowAlertConflict("Recommendation fields are invalid") from exc
        public_id = str(uuid.uuid4())
        created_at = self._utc()
        alert = Alert(
            alert_id=public_id, type=alert_type, severity=severity,
            status=AlertStatus.NEW,
            title=f"{alert_type.value.replace('_', ' ').title()} Detected",
            description="Alert explicitly created from a live metadata-flow policy recommendation.",
            source_category="live_metadata_flow",
            predicted_canonical_label=record.predicted_canonical_label,
            confidence_score=record.confidence_score or 0.0,
            risk_score=record.risk_score or 0.0,
            model_version=record.model_version,
            schema_version=record.flow_schema_version,
            created_at=created_at, deduplication_key=origin,
            safe_metadata={
                "evaluation_id": record.evaluation_id,
                "occurrence_count": 1,
                "policy_version": record.policy_version,
                "reason_code": record.reason_code,
            },
        )
        try:
            self._persistence.store_alert(
                alert, policy_version=record.policy_version,
                reason_code=record.reason_code,
            )
        except ConflictError as exc:
            existing = self._persistence.find_by_deduplication_key(origin)
            if not existing:
                raise LiveFlowAlertConflict(
                    "Alert uniqueness conflict could not be resolved"
                ) from exc
            public_id = existing["public_alert_id"]
        self._state.mark_alert_persisted(evaluation_id, public_id, created_at)
        logger.info(
            "Live-flow alert request evaluation_id=%s alert_id=%s replay=false",
            evaluation_id, public_id,
        )
        return public_id, False

    @staticmethod
    def _origin_key(record):
        material = "|".join((
            record.source_category, record.evaluation_id,
            record.evaluation_schema_version, record.model_version or "",
            record.policy_version,
        ))
        return hashlib.sha256(material.encode()).hexdigest()
