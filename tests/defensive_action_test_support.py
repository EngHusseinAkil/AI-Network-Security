from datetime import datetime, timezone

from backend.services.defensive_action_service import DefensiveActionService
from defense.config import DefensiveActionConfig
from defense.providers import FakeDefensiveActionProvider
from defense.resolver import TrustedDefensiveTargetResolver


def alert(status="new", severity="high", source="test_demo"):
    return {
        "public_alert_id": "alert-1", "status": status, "severity": severity,
        "source_category": source, "version": 1,
    }


class Alerts:
    def __init__(self, item=None):
        self.item = alert() if item is None else item

    def get_alert(self, alert_id):
        return self.item if self.item and self.item["public_alert_id"] == alert_id else None


class Actions:
    def __init__(self):
        self.items = {}
        self.events = []

    def find_by_request_identity(self, identity):
        return next((x for x in self.items.values() if x["request_identity"] == identity), None)

    def active_for_target(self, reference):
        return next((x for x in self.items.values()
                     if x["target_reference_id"] == reference and x["status"] == "applied"), None)

    def create_pending(self, **v):
        self.events.append("pending")
        item = {
            "action_id": v["public_action_id"], "alert_id": v["alert_public_id"],
            "request_identity": v["request_identity"], "action_type": v["action_type"],
            "target_category": v["target_category"],
            "target_reference_id": v["target_reference_id"],
            "masked_target_label": v["masked_target_label"],
            "provider_category": v["provider_category"],
            "provider_reference": None, "requested_at": v["requested_at"],
            "applied_at": None, "expires_at": None, "removed_at": None,
            "status": "pending", "safe_error_category": None,
            "reason_code": v["reason_code"], "duration_seconds": v["duration_seconds"],
            "schema_version": v["action_schema_version"],
            "removal_request_identity": None,
        }
        self.items[item["action_id"]] = item
        return item

    def complete_apply(self, action_id, status, now, expires, error, reference):
        item = self.items[action_id]
        item.update(status=status, applied_at=now if status == "applied" else None,
                    expires_at=expires if status == "applied" else None,
                    safe_error_category=error, provider_reference=reference)
        return dict(item)

    def get(self, action_id):
        value = self.items.get(action_id)
        return dict(value) if value else None

    def reserve_remove(self, action_id, identity):
        item = self.items[action_id]
        if item["removal_request_identity"] == identity:
            return dict(item), True
        if item["removal_request_identity"]:
            if item["status"] == "applied" and item["safe_error_category"]:
                item["removal_request_identity"] = identity
                item["safe_error_category"] = None
                return dict(item), False
            return dict(item), False
        item["removal_request_identity"] = identity
        return dict(item), False

    def complete_remove(self, action_id, identity, status, now, error=None):
        item = self.items[action_id]
        item.update(
            status="removed" if status == "removed" else item["status"],
            removed_at=now if status == "removed" else None,
            safe_error_category=error,
        )
        return dict(item)


def make_service(outcome="applied", remove_outcome="removed", item=None, mappings=None):
    config = DefensiveActionConfig(
        enabled=True, provider="fake", fake_provider_permitted=True
    )
    provider = FakeDefensiveActionProvider(outcome, remove_outcome)
    actions = Actions()
    resolver = TrustedDefensiveTargetResolver({
        "alert-1": {
            "reference_id": "target-ref-1", "category": "demo_device",
            "masked_label": "Demo target ****1", "native_value": "test-only-native",
        }
    } if mappings is None else mappings)
    return (
        DefensiveActionService(
            config, resolver, provider, Alerts(item), actions, "secret",
            utc_clock=lambda: datetime.now(timezone.utc),
        ),
        provider, actions,
    )
