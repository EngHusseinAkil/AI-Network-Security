from dataclasses import dataclass
from datetime import datetime, timezone

DELIVERY_STATUSES = {"pending", "sent", "failed", "unavailable", "timeout", "unknown"}


def _utc(value, name):
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class AlertNotificationMessage:
    notification_id: str
    alert_id: str
    masked_recipient_label: str
    subject: str
    body: str
    alert_type: str
    severity: str
    reason_code: str | None
    predicted_label: str | None
    alert_created_at: datetime
    schema_version: str

    def __post_init__(self):
        object.__setattr__(self, "alert_created_at", _utc(
            self.alert_created_at, "alert_created_at"
        ))
        if "\r" in self.subject or "\n" in self.subject:
            raise ValueError("subject contains a header injection sequence")


@dataclass(frozen=True, slots=True)
class NotificationProviderResult:
    status: str
    safe_error_category: str | None = None
    provider_message_reference: str | None = None

    def __post_init__(self):
        if self.status not in DELIVERY_STATUSES - {"pending"}:
            raise ValueError("invalid provider result status")


@dataclass(frozen=True, slots=True)
class AlertNotificationDelivery:
    delivery_id: str
    alert_id: str
    provider_category: str
    masked_recipient_label: str
    requested_at: datetime
    completed_at: datetime | None
    status: str
    safe_error_category: str | None
    attempt_number: int
    schema_version: str
    provider_message_reference: str | None = None

    def __post_init__(self):
        if self.status not in DELIVERY_STATUSES:
            raise ValueError("invalid delivery status")
        object.__setattr__(self, "requested_at", _utc(self.requested_at, "requested_at"))
        object.__setattr__(self, "completed_at", _utc(self.completed_at, "completed_at"))

