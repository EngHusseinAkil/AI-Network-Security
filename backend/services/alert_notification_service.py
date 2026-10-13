from datetime import datetime, timezone
import hashlib
import logging
import secrets
import time
import uuid

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from utils.exceptions import ConflictError

from notifications.models import AlertNotificationMessage

TOKEN_SALT = "alert-notification-request"
TOKEN_PURPOSE = "explicit-alert-notification-v1"
TOKEN_MAX_AGE = 300
logger = logging.getLogger(__name__)


class AlertNotificationError(Exception):
    status_code = 400


class NotificationDisabled(AlertNotificationError):
    status_code = 403


class NotificationMissingAlert(AlertNotificationError):
    status_code = 404


class NotificationConflict(AlertNotificationError):
    status_code = 409


class NotificationUnavailable(AlertNotificationError):
    status_code = 503


class AlertNotificationService:
    def __init__(self, config, provider, alert_persistence, delivery_persistence,
                 secret_key, utc_clock=None):
        self.config = config
        self._provider = provider
        self._alerts = alert_persistence
        self._deliveries = delivery_persistence
        self._serializer = URLSafeTimedSerializer(secret_key, salt=TOKEN_SALT)
        self._utc = utc_clock or (lambda: datetime.now(timezone.utc))

    def eligibility(self, alert):
        if not self.config.enabled:
            return False, "notifications_disabled"
        if not self.config.recipient:
            return False, "recipient_not_configured"
        if alert.get("status") not in {"new", "acknowledged"}:
            return False, "alert_terminal"
        required = ("public_alert_id", "alert_type", "severity", "title", "created_at")
        if any(not alert.get(key) for key in required):
            return False, "alert_incomplete"
        return True, None

    def generate_request_token(self, alert_id, session_csrf):
        alert = self._alerts.get_alert(alert_id)
        if not alert or not self.eligibility(alert)[0]:
            return None
        return self._serializer.dumps({
            "purpose": TOKEN_PURPOSE,
            "alert_id": alert_id,
            "alert_version": alert["version"],
            "schema_version": self.config.schema_version,
            "nonce": secrets.token_hex(16),
            "session_digest": hashlib.sha256(session_csrf.encode()).hexdigest(),
        })

    def notify(self, alert_id, token, session_csrf):
        from utils.signed_tokens import is_canonical_signed_token
        if not is_canonical_signed_token(token):
            raise AlertNotificationError("Invalid or expired notification request")
        try:
            claims = self._serializer.loads(token, max_age=TOKEN_MAX_AGE)
        except (BadSignature, SignatureExpired) as exc:
            raise AlertNotificationError("Invalid or expired notification request") from exc
        if claims.get("purpose") != TOKEN_PURPOSE or claims.get("alert_id") != alert_id:
            raise AlertNotificationError("Notification request does not match alert")
        digest = hashlib.sha256(session_csrf.encode()).hexdigest()
        if not secrets.compare_digest(claims.get("session_digest", ""), digest):
            raise NotificationDisabled("Notification request session mismatch")
        if claims.get("schema_version") != self.config.schema_version:
            raise AlertNotificationError("Unsupported notification request schema")

        alert = self._alerts.get_alert(alert_id)
        if alert is None:
            raise NotificationMissingAlert("Alert not found")
        if claims.get("alert_version") != alert.get("version"):
            raise NotificationConflict("Alert changed after notification action was rendered")
        eligible, category = self.eligibility(alert)
        if not eligible:
            if category == "notifications_disabled":
                raise NotificationDisabled("Notifications are disabled")
            if category == "recipient_not_configured":
                raise NotificationUnavailable("Notification recipient is unavailable")
            raise NotificationConflict("Alert is not eligible for notification")

        identity = hashlib.sha256("|".join((
            alert_id, self.config.provider, self.config.schema_version,
            claims.get("nonce", ""),
        )).encode()).hexdigest()
        existing = self._deliveries.find_by_request_identity(identity)
        if existing:
            return existing, True

        delivery_id = str(uuid.uuid4())
        requested_at = self._utc()
        pending = {
            "public_delivery_id": delivery_id,
            "alert_public_id": alert_id,
            "request_identity": identity,
            "provider_category": self.config.provider,
            "masked_recipient_label": self.config.recipient_label,
            "requested_at": requested_at,
            "completed_at": None,
            "status": "pending",
            "safe_error_category": None,
            "attempt_number": 1,
            "notification_schema_version": self.config.schema_version,
            "provider_message_reference": None,
        }
        try:
            self._deliveries.create_pending(**pending)
        except ConflictError:
            existing = self._deliveries.find_by_request_identity(identity)
            if existing:
                return existing, True
            raise NotificationConflict("Notification request is already in progress")

        message = self._message(alert, delivery_id)
        started = time.monotonic()
        try:
            result = self._provider.send(
                message, self.config.provider_timeout_seconds
            )
        except TimeoutError:
            from notifications.models import NotificationProviderResult
            result = NotificationProviderResult("timeout", "provider_timeout")
        except Exception:
            from notifications.models import NotificationProviderResult
            result = NotificationProviderResult("unknown", "provider_failure")
        completed = self._deliveries.complete(
            delivery_id, result.status, self._utc(),
            result.safe_error_category, result.provider_message_reference,
        )
        logger.info(
            "Explicit notification alert_id=%s delivery_id=%s provider=%s "
            "outcome=%s error_category=%s duration_ms=%d",
            alert_id, delivery_id, self.config.provider, result.status,
            result.safe_error_category,
            int((time.monotonic() - started) * 1000),
        )
        if result.status != "sent":
            raise NotificationUnavailable(
                f"Notification delivery {result.safe_error_category or 'failed'}"
            )
        return completed, False

    def _message(self, alert, delivery_id):
        created = alert["created_at"]
        if isinstance(created, str):
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        subject = f"Security alert: {alert['title']}"[:self.config.subject_max_length]
        body = (
            f"Alert {alert['public_alert_id']} has severity {alert['severity']} and "
            f"type {alert['alert_type']}. This alert is AI-assisted and is not proof "
            "of malicious activity. Operator investigation is required."
        )[:self.config.body_max_length]
        return AlertNotificationMessage(
            delivery_id, alert["public_alert_id"], self.config.recipient_label,
            subject, body, alert["alert_type"], alert["severity"],
            alert.get("reason_code"), alert.get("predicted_label"), created,
            self.config.schema_version,
        )
