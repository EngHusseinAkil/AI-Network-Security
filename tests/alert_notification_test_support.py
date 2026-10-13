from datetime import datetime, timezone

from notifications.config import AlertNotificationConfig
from notifications.providers import FakeNotificationProvider
from backend.services.alert_notification_service import AlertNotificationService


def alert(status="new"):
    return {
        "public_alert_id": "alert-1", "alert_type": "suspected_ddos",
        "severity": "high", "status": status, "title": "DDoS detected",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "version": 1, "reason_code": "risk_threshold_met",
        "predicted_label": "ddos",
    }


class Alerts:
    def __init__(self, value=None):
        self.value = value if value is not None else alert()

    def get_alert(self, alert_id):
        return self.value if self.value and self.value["public_alert_id"] == alert_id else None


class Deliveries:
    def __init__(self):
        self.items = {}

    def find_by_request_identity(self, identity):
        return self.items.get(identity)

    def create_pending(self, **values):
        item = {
            "delivery_id": values["public_delivery_id"],
            "alert_id": values["alert_public_id"],
            "provider_category": values["provider_category"],
            "masked_recipient_label": values["masked_recipient_label"],
            "requested_at": values["requested_at"], "completed_at": None,
            "status": "pending", "safe_error_category": None,
            "attempt_number": 1,
            "schema_version": values["notification_schema_version"],
            "provider_message_reference": None,
        }
        self.items[values["request_identity"]] = item
        return item

    def complete(self, delivery_id, status, completed_at, error=None, reference=None):
        item = next(item for item in self.items.values() if item["delivery_id"] == delivery_id)
        item.update(status=status, completed_at=completed_at,
                    safe_error_category=error, provider_message_reference=reference)
        return dict(item)


def service(outcome="sent", alert_value=None):
    config = AlertNotificationConfig(
        enabled=True, provider="fake", recipient="security@example.test",
        recipient_label="s***@example.test", fake_provider_permitted=True,
    )
    provider = FakeNotificationProvider(outcome)
    deliveries = Deliveries()
    return (
        AlertNotificationService(
            config, provider, Alerts(alert_value), deliveries, "secret"
        ),
        provider, deliveries,
    )
