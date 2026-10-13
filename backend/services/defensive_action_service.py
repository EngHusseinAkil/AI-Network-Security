from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import uuid

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from utils.exceptions import ConflictError

from defense.models import DefensiveActionRecommendation

APPLY_PURPOSE = "defensive-action-confirmation-v1"
REMOVE_PURPOSE = "defensive-action-removal-v1"
TOKEN_SALT = "defensive-action-confirmation"


class DefensiveActionError(Exception):
    status_code = 400


class DefensiveActionDisabled(DefensiveActionError):
    status_code = 403


class DefensiveAlertMissing(DefensiveActionError):
    status_code = 404


class DefensiveActionConflict(DefensiveActionError):
    status_code = 409


class DefensiveProviderUnavailable(DefensiveActionError):
    status_code = 503


class DefensiveActionService:
    def __init__(self, config, resolver, provider, alert_persistence,
                 action_persistence, secret_key, utc_clock=None):
        self.config = config
        self._resolver = resolver
        self._provider = provider
        self._alerts = alert_persistence
        self._actions = action_persistence
        self._serializer = URLSafeTimedSerializer(secret_key, salt=TOKEN_SALT)
        self._utc = utc_clock or (lambda: datetime.now(timezone.utc))

    def recommendation(self, alert):
        now = self._utc()
        target = self._resolver.resolve(alert) if alert else None
        reason = None
        if not self.config.enabled:
            reason = "defensive_actions_disabled"
        elif not alert or alert.get("status") not in {"new", "acknowledged"}:
            reason = "alert_status_ineligible"
        elif self._severity_rank(alert.get("severity")) < self._severity_rank(
            self.config.minimum_severity
        ):
            reason = "alert_severity_ineligible"
        elif target is None:
            reason = "no_trusted_actionable_target"
        elif self.config.provider == "unavailable":
            reason = "provider_unavailable"
        elif self._provider.status() != "available":
            reason = "provider_unavailable"
        elif self._actions.active_for_target(target.reference_id):
            reason = "conflicting_active_action"
        material = "|".join((
            alert.get("public_alert_id", "missing") if alert else "missing",
            target.reference_id if target else "none",
            self.config.schema_version,
        ))
        return DefensiveActionRecommendation(
            recommendation_id=hashlib.sha256(material.encode()).hexdigest(),
            alert_id=alert.get("public_alert_id", "missing") if alert else "missing",
            action_type="temporary_deny",
            target_category=target.category if target else None,
            masked_target_label=target.masked_label if target else None,
            duration_seconds=self.config.default_duration_seconds,
            reason_code="operator_defensive_review",
            created_at=now,
            schema_version=self.config.schema_version,
            eligible=reason is None,
            ineligibility_reason=reason,
        )

    def generate_apply_token(self, alert, session_csrf):
        recommendation = self.recommendation(alert)
        if not recommendation.eligible:
            return None
        target = self._resolver.resolve(alert)
        return self._serializer.dumps({
            "purpose": APPLY_PURPOSE,
            "alert_id": alert["public_alert_id"],
            "recommendation_id": recommendation.recommendation_id,
            "action_type": "temporary_deny",
            "schema_version": self.config.schema_version,
            "target_reference_id": target.reference_id,
            "duration_seconds": recommendation.duration_seconds,
            "nonce": secrets.token_hex(16),
            "session_digest": hashlib.sha256(session_csrf.encode()).hexdigest(),
        })

    def generate_remove_token(self, action, session_csrf):
        if not self.config.enabled or action.get("status") != "applied":
            return None
        return self._serializer.dumps({
            "purpose": REMOVE_PURPOSE,
            "alert_id": action["alert_id"],
            "action_id": action["action_id"],
            "schema_version": self.config.schema_version,
            "nonce": secrets.token_hex(16),
            "session_digest": hashlib.sha256(session_csrf.encode()).hexdigest(),
        })

    def apply(self, alert_id, token, session_csrf):
        claims = self._claims(token, APPLY_PURPOSE, session_csrf)
        if claims.get("alert_id") != alert_id:
            raise DefensiveActionError("Confirmation does not match alert")
        if not self.config.enabled:
            raise DefensiveActionDisabled("Defensive actions are disabled")
        alert = self._alerts.get_alert(alert_id)
        if alert is None:
            raise DefensiveAlertMissing("Alert not found")
        identity = self._identity(alert_id, claims["nonce"], "apply")
        existing = self._actions.find_by_request_identity(identity)
        if existing:
            return existing, True
        recommendation = self.recommendation(alert)
        target = self._resolver.resolve(alert)
        if (
            not recommendation.eligible
            or target is None
            or claims.get("recommendation_id") != recommendation.recommendation_id
            or claims.get("target_reference_id") != target.reference_id
            or claims.get("duration_seconds") != recommendation.duration_seconds
            or claims.get("action_type") != "temporary_deny"
        ):
            raise DefensiveActionConflict("Defensive recommendation is ineligible or changed")
        if self._actions.active_for_target(target.reference_id):
            raise DefensiveActionConflict("A conflicting defensive action is active")
        action_id = str(uuid.uuid4())
        now = self._utc()
        try:
            self._actions.create_pending(
                public_action_id=action_id, alert_public_id=alert_id,
                request_identity=identity, action_type="temporary_deny",
                target_category=target.category,
                target_reference_id=target.reference_id,
                masked_target_label=target.masked_label,
                provider_category=self.config.provider, provider_reference=None,
                requested_at=now, applied_at=None, expires_at=None, removed_at=None,
                status="pending", safe_error_category=None,
                reason_code=recommendation.reason_code,
                duration_seconds=recommendation.duration_seconds,
                action_schema_version=self.config.schema_version,
                removal_request_identity=None,
            )
        except ConflictError:
            existing = self._actions.find_by_request_identity(identity)
            if existing:
                return existing, True
            raise DefensiveActionConflict("Defensive request conflict")
        try:
            result = self._provider.apply_temporary_deny(
                target, recommendation.duration_seconds
            )
        except TimeoutError:
            from defense.models import DefensiveProviderResult
            result = DefensiveProviderResult("timeout", "provider_timeout")
        except Exception:
            from defense.models import DefensiveProviderResult
            result = DefensiveProviderResult("unknown", "provider_failure")
        expires = now + timedelta(seconds=recommendation.duration_seconds)
        completed = self._actions.complete_apply(
            action_id, result.status, self._utc(), expires,
            result.safe_error_category, result.provider_reference,
        )
        if result.status != "applied":
            raise DefensiveProviderUnavailable("Defensive provider action failed")
        return completed, False

    def remove(self, alert_id, action_id, token, session_csrf):
        claims = self._claims(token, REMOVE_PURPOSE, session_csrf)
        if claims.get("alert_id") != alert_id or claims.get("action_id") != action_id:
            raise DefensiveActionError("Removal confirmation does not match action")
        if not self.config.enabled:
            raise DefensiveActionDisabled("Defensive actions are disabled")
        action = self._actions.get(action_id)
        if action is None or action["alert_id"] != alert_id:
            raise DefensiveAlertMissing("Defensive action not found")
        identity = self._identity(action_id, claims["nonce"], "remove")
        if action["status"] == "removed":
            return action, True
        if action["status"] != "applied":
            raise DefensiveActionConflict("Defensive action cannot be removed")
        reserved, replayed = self._actions.reserve_remove(action_id, identity)
        if replayed:
            return reserved, True
        if reserved["removal_request_identity"] != identity:
            raise DefensiveActionConflict("Another removal request exists")
        alert = self._alerts.get_alert(alert_id)
        target = self._resolver.resolve(alert) if alert else None
        if target is None or target.reference_id != action["target_reference_id"]:
            raise DefensiveActionConflict("Trusted target is unavailable")
        try:
            result = self._provider.remove_temporary_deny(
                target, action["provider_reference"]
            )
        except TimeoutError:
            from defense.models import DefensiveProviderResult
            result = DefensiveProviderResult("timeout", "provider_timeout")
        except Exception:
            from defense.models import DefensiveProviderResult
            result = DefensiveProviderResult("unknown", "provider_failure")
        status = "removed" if result.status == "applied" else result.status
        completed = self._actions.complete_remove(
            action_id, identity, status, self._utc(), result.safe_error_category
        )
        if status != "removed":
            raise DefensiveProviderUnavailable("Defensive removal failed")
        return completed, False

    def _claims(self, token, purpose, session_csrf):
        from utils.signed_tokens import is_canonical_signed_token
        if not is_canonical_signed_token(token):
            raise DefensiveActionError("Invalid or expired confirmation")
        try:
            claims = self._serializer.loads(
                token, max_age=self.config.token_max_age_seconds
            )
        except (BadSignature, SignatureExpired) as exc:
            raise DefensiveActionError("Invalid or expired confirmation") from exc
        if claims.get("purpose") != purpose:
            raise DefensiveActionError("Invalid confirmation purpose")
        digest = hashlib.sha256(session_csrf.encode()).hexdigest()
        if not secrets.compare_digest(claims.get("session_digest", ""), digest):
            raise DefensiveActionDisabled("Confirmation session mismatch")
        if claims.get("schema_version") != self.config.schema_version:
            raise DefensiveActionError("Unsupported confirmation schema")
        return claims

    @staticmethod
    def _identity(subject, nonce, operation):
        return hashlib.sha256(f"{subject}|{operation}|{nonce}".encode()).hexdigest()

    @staticmethod
    def _severity_rank(value):
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, -1)
