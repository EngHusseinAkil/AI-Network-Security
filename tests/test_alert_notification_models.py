from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import pytest

from notifications.models import AlertNotificationDelivery, AlertNotificationMessage


def test_message_is_immutable_and_rejects_header_injection():
    message = AlertNotificationMessage(
        "delivery", "alert", "masked", "Subject", "Body", "type", "high",
        None, None, datetime.now(timezone.utc), "alert-notification-v1",
    )
    with pytest.raises(FrozenInstanceError):
        message.subject = "changed"
    with pytest.raises(ValueError):
        AlertNotificationMessage(
            "delivery", "alert", "masked", "bad\nsubject", "Body", "type",
            "high", None, None, datetime.now(timezone.utc), "v1",
        )


def test_delivery_contract_has_no_secret_or_raw_response_fields():
    fields = AlertNotificationDelivery.__dataclass_fields__
    assert not {"credentials", "recipient", "raw_response", "message_body"} & set(fields)
