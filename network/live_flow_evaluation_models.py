"""Immutable, safe records for explicit metadata-flow evaluation."""
from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Optional

SOURCE_CATEGORY = "live_metadata_flow"


def _safe_text(value, name, optional=False):
    if value is None and optional:
        return
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{name} must be a bounded safe string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} contains control characters")


def _score(value, name, optional=False):
    if value is None and optional:
        return
    if (not isinstance(value, (int, float)) or isinstance(value, bool)
            or not math.isfinite(value) or not 0 <= value <= 1):
        raise ValueError(f"{name} must be finite and between 0 and 1")


@dataclass(frozen=True, slots=True)
class LiveFlowEvaluationRecord:
    evaluation_id: str
    evaluation_key: str
    flow_id: str
    flow_schema_version: str
    evaluated_at: datetime
    feature_compatible: bool
    inference_status: str
    predicted_canonical_label: Optional[str]
    confidence_score: Optional[float]
    risk_score: Optional[float]
    model_version: Optional[str]
    policy_status: str
    alert_recommended: bool
    proposed_alert_type: Optional[str]
    proposed_severity: Optional[str]
    reason_code: Optional[str]
    policy_version: str
    source_category: str
    safe_error_category: Optional[str]
    evaluation_schema_version: str
    alert_persisted: bool = False
    persisted_alert_id: Optional[str] = None
    alert_created_at: Optional[datetime] = None
    notification_sent: bool = False
    blocking_executed: bool = False

    def __post_init__(self):
        for name in ("evaluation_id", "evaluation_key", "flow_id", "flow_schema_version",
                     "inference_status", "policy_status", "policy_version",
                     "source_category", "evaluation_schema_version"):
            _safe_text(getattr(self, name), name)
        for name in ("predicted_canonical_label", "model_version", "proposed_alert_type",
                     "proposed_severity", "reason_code", "safe_error_category",
                     "persisted_alert_id"):
            _safe_text(getattr(self, name), name, optional=True)
        if self.evaluated_at.tzinfo is None:
            raise ValueError("evaluated_at must be timezone-aware")
        object.__setattr__(self, "evaluated_at", self.evaluated_at.astimezone(timezone.utc))
        if not isinstance(self.feature_compatible, bool):
            raise ValueError("feature_compatible must be boolean")
        _score(self.confidence_score, "confidence_score", optional=True)
        _score(self.risk_score, "risk_score", optional=True)
        if self.source_category != SOURCE_CATEGORY:
            raise ValueError("source_category must be live_metadata_flow")
        for name in ("alert_recommended", "alert_persisted",
                     "notification_sent", "blocking_executed"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be boolean")
        if self.alert_created_at is not None:
            if self.alert_created_at.tzinfo is None:
                raise ValueError("alert_created_at must be timezone-aware")
            object.__setattr__(self, "alert_created_at", self.alert_created_at.astimezone(timezone.utc))
        if self.notification_sent or self.blocking_executed:
            raise ValueError("notification and blocking flags must remain false")
        if self.alert_persisted != bool(self.persisted_alert_id and self.alert_created_at):
            raise ValueError("persisted alert linkage must be complete")

    @property
    def successful(self):
        return self.inference_status == "success" and self.policy_status == "success"


@dataclass(frozen=True, slots=True)
class LiveFlowEvaluationSnapshot:
    evaluation_request_count: int
    flows_considered_count: int
    flows_skipped_already_evaluated_count: int
    incompatible_flow_count: int
    successful_inference_count: int
    failed_inference_count: int
    successful_policy_count: int
    failed_policy_count: int
    recommendation_count: int
    retained_evaluation_count: int
    evaluation_eviction_count: int
    successfully_evaluated_flow_count: int
    latest_record: Optional[LiveFlowEvaluationRecord]
    recent_records: tuple[LiveFlowEvaluationRecord, ...]


@dataclass(frozen=True, slots=True)
class LiveFlowEvaluationRequestResult:
    considered_count: int
    retained_count: int
    skipped_count: int
