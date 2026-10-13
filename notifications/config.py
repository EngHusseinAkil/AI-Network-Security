from dataclasses import dataclass


def _bounded_text(value, name, maximum, required=True):
    if value is None and not required:
        return
    if not isinstance(value, str) or (required and not value) or len(value) > maximum:
        raise ValueError(f"{name} must be a bounded string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} contains control characters")


@dataclass(frozen=True, slots=True)
class AlertNotificationConfig:
    enabled: bool = False
    provider: str = "email"
    recipient: str | None = None
    recipient_label: str = "Configured security mailbox"
    fake_provider_permitted: bool = False
    max_delivery_attempts_per_request: int = 1
    max_retained_deliveries: int = 1_000
    subject_max_length: int = 160
    body_max_length: int = 2_000
    provider_timeout_seconds: float = 10.0
    schema_version: str = "alert-notification-v1"

    def __post_init__(self):
        if not isinstance(self.enabled, bool) or not isinstance(
            self.fake_provider_permitted, bool
        ):
            raise ValueError("notification flags must be boolean")
        if self.provider not in {"email", "fake"}:
            raise ValueError("notification provider is not allowlisted")
        if self.provider == "fake" and not self.fake_provider_permitted:
            raise ValueError("fake provider is restricted to testing or demo mode")
        _bounded_text(self.recipient, "recipient", 254, required=False)
        _bounded_text(self.recipient_label, "recipient_label", 128)
        _bounded_text(self.schema_version, "schema_version", 64)
        for name, minimum, maximum in (
            ("max_delivery_attempts_per_request", 1, 1),
            ("max_retained_deliveries", 1, 10_000),
            ("subject_max_length", 32, 255),
            ("body_max_length", 128, 10_000),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{name} is outside its safe bounds")
        timeout = self.provider_timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 60:
            raise ValueError("provider_timeout_seconds is outside its safe bounds")

