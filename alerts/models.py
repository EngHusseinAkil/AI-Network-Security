"""
Alert Domain Model.

Defines the framework-neutral immutable alert object and lifecycle transitions.
"""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import hashlib
import json

from alerts.constants import AlertType, AlertSeverity, AlertStatus, VALID_TRANSITIONS
from alerts.exceptions import AlertValidationError
from utils.time_utils import get_current_utc_time


def _check_aware_utc(dt: Optional[datetime], field_name: str):
    if dt is not None:
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            raise AlertValidationError(f"Timestamp {field_name} must be timezone-aware.")
        if dt.tzinfo != timezone.utc:
            raise AlertValidationError(f"Timestamp {field_name} must use timezone.utc.")


@dataclass(frozen=True)
class Alert:
    """
    Immutable domain object representing a single alert.
    Uses frozen=True to prevent accidental modification; use `transition_to` for lifecycle updates.
    """
    alert_id: str
    type: AlertType
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: str
    source_category: str

    # AI / Inference context
    predicted_canonical_label: Optional[str]
    confidence_score: float
    risk_score: float
    model_version: Optional[str]
    schema_version: Optional[str]

    # Timestamps
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    dismissed_at: Optional[datetime] = None
    # Identity
    deduplication_key: str = ""
    version: int = 1

    # Additional context
    safe_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Validate enums
        if not isinstance(self.type, AlertType):
            raise AlertValidationError(f"Invalid alert type: {self.type}")
        if not isinstance(self.severity, AlertSeverity):
            raise AlertValidationError(f"Invalid alert severity: {self.severity}")
        if not isinstance(self.status, AlertStatus):
            raise AlertValidationError(f"Invalid alert status: {self.status}")

        # Validate scores
        if not (0.0 <= self.confidence_score <= 1.0):
            raise AlertValidationError("confidence_score must be between 0.0 and 1.0")
        if not (0.0 <= self.risk_score <= 1.0):
            raise AlertValidationError("risk_score must be between 0.0 and 1.0")

        # Validate timestamps
        _check_aware_utc(self.created_at, "created_at")
        _check_aware_utc(self.acknowledged_at, "acknowledged_at")
        _check_aware_utc(self.resolved_at, "resolved_at")
        _check_aware_utc(self.dismissed_at, "dismissed_at")

        # Automatically compute deduplication_key if not provided, though it normally should be passed in.
        # However, to maintain immutability and ensure deterministic keys, we allow external computation.
        if not self.deduplication_key:
            raise AlertValidationError("deduplication_key is required")

    def transition_to(self, new_status: AlertStatus, timestamp: datetime) -> "Alert":
        """
        Returns a new Alert instance with the updated status and timestamp,
        enforcing valid lifecycle transitions and timestamp consistency.
        """
        if not isinstance(new_status, AlertStatus):
            raise AlertValidationError(f"Invalid alert status: {new_status}")

        _check_aware_utc(timestamp, "transition timestamp")

        # Validate transition
        allowed_next = VALID_TRANSITIONS.get(self.status, set())
        if new_status not in allowed_next:
            raise AlertValidationError(f"Invalid transition from {self.status.value} to {new_status.value}")

        # Enforce timestamp consistency
        if timestamp < self.created_at:
            raise AlertValidationError("Transition timestamp cannot be earlier than created_at")

        latest_existing = max(filter(None, [self.created_at, self.acknowledged_at, self.resolved_at, self.dismissed_at]))
        if timestamp < latest_existing:
            raise AlertValidationError("Transition timestamp cannot be earlier than previous state changes")

        updates = {"status": new_status, "version": self.version + 1}
        if new_status == AlertStatus.ACKNOWLEDGED:
            updates["acknowledged_at"] = timestamp
        elif new_status == AlertStatus.RESOLVED:
            updates["resolved_at"] = timestamp
        elif new_status == AlertStatus.DISMISSED:
            updates["dismissed_at"] = timestamp

        return replace(self, **updates)

    @staticmethod
    def generate_duplicate_key(alert_type: AlertType, pseudonymous_source_key: str, model_version: str, time_bucket_iso: str) -> str:
        """
        Generates a deterministic SHA-256 deduplication key.
        The inputs must be safe, pseudonymous values, not raw IP/MACs.
        """
        # We explicitly document that pseudonymous_source_key must not be raw PII/IP
        components = [
            str(alert_type.value),
            str(pseudonymous_source_key),
            str(model_version),
            str(time_bucket_iso)
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()
