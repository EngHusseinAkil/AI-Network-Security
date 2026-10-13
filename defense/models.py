from dataclasses import dataclass
from datetime import datetime, timezone

ACTION_TYPES = {"temporary_deny", "remove_temporary_deny"}
ACTION_STATUSES = {
    "pending", "applied", "failed", "timeout", "expired",
    "removed", "unavailable", "unknown",
}


def _utc(value, name):
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class DefensiveTarget:
    reference_id: str
    category: str
    masked_label: str
    native_value: str


@dataclass(frozen=True, slots=True)
class DefensiveActionRecommendation:
    recommendation_id: str
    alert_id: str
    action_type: str
    target_category: str | None
    masked_target_label: str | None
    duration_seconds: int
    reason_code: str
    created_at: datetime
    schema_version: str
    eligible: bool
    ineligibility_reason: str | None = None

    def __post_init__(self):
        if self.action_type not in ACTION_TYPES:
            raise ValueError("unsupported defensive action type")
        object.__setattr__(self, "created_at", _utc(self.created_at, "created_at"))


@dataclass(frozen=True, slots=True)
class DefensiveProviderResult:
    status: str
    safe_error_category: str | None = None
    provider_reference: str | None = None

    def __post_init__(self):
        if self.status not in ACTION_STATUSES - {"pending", "expired", "removed"}:
            raise ValueError("invalid provider result")
