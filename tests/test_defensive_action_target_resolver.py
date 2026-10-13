from defense.resolver import TrustedDefensiveTargetResolver
from tests.defensive_action_test_support import alert
import pytest


def test_missing_mapping_does_not_fabricate_target():
    assert TrustedDefensiveTargetResolver().resolve(alert()) is None


def test_trusted_mapping_returns_internal_target_only():
    resolver = TrustedDefensiveTargetResolver({"alert-1": {
        "reference_id": "safe-ref", "category": "demo_device",
        "masked_label": "Target ****", "native_value": "native-test-value",
    }})
    target = resolver.resolve(alert())
    assert target.reference_id == "safe-ref" and target.masked_label == "Target ****"


@pytest.mark.parametrize("label", ["192.0.2.1", "00:11:22:33:44:55", "unmasked"])
def test_mapping_rejects_native_or_unmasked_display_labels(label):
    with pytest.raises(ValueError):
        TrustedDefensiveTargetResolver({"alert-1": {
            "reference_id": "safe-ref", "category": "demo_device",
            "masked_label": label, "native_value": "internal",
        }})
