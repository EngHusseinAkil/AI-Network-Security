from .models import DefensiveTarget
import ipaddress
import re


class TrustedDefensiveTargetResolver:
    def __init__(self, mappings=None):
        self._mappings = dict(mappings or {})
        for value in self._mappings.values():
            self._validate(value)

    def resolve(self, alert):
        value = self._mappings.get(alert.get("public_alert_id"))
        if not value:
            return None
        return DefensiveTarget(
            reference_id=value["reference_id"],
            category=value["category"],
            masked_label=value["masked_label"],
            native_value=value["native_value"],
        )

    @staticmethod
    def _validate(value):
        required = ("reference_id", "category", "masked_label", "native_value")
        if any(not isinstance(value.get(key), str) or not value[key] for key in required):
            raise ValueError("trusted target mapping is incomplete")
        if any(
            len(value[key]) > 128
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value[key])
            for key in required
        ):
            raise ValueError("trusted target mapping contains unsafe text")
        if value["category"] not in {"demo_device", "pseudonymous_device"}:
            raise ValueError("trusted target category is not supported")
        label = value["masked_label"]
        try:
            ipaddress.ip_address(label)
            raise ValueError("masked label must not expose an IP address")
        except ValueError as exc:
            if str(exc) == "masked label must not expose an IP address":
                raise
        if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", label):
            raise ValueError("masked label must not expose a MAC address")
        if "*" not in label:
            raise ValueError("masked label must visibly mask the target")
