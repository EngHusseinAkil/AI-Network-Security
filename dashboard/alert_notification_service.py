def _iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def _safe_delivery(item):
    return {
        "delivery_id": item["delivery_id"],
        "provider_category": item["provider_category"],
        "masked_recipient_label": item["masked_recipient_label"],
        "requested_at": _iso(item["requested_at"]),
        "completed_at": _iso(item["completed_at"]),
        "status": item["status"],
        "safe_error_category": item["safe_error_category"],
        "attempt_number": item["attempt_number"],
        "schema_version": item["schema_version"],
    }


class DashboardAlertNotificationService:
    def __init__(self, notification_service, delivery_service):
        self._notifications = notification_service
        self._deliveries = delivery_service

    def presentation(self, alert, session_csrf):
        attempts = (
            self._deliveries.for_alert(alert["public_alert_id"])
            if self._notifications.config.enabled else ()
        )
        eligible, reason = self._notifications.eligibility(alert)
        return {
            "enabled": self._notifications.config.enabled,
            "eligible": eligible,
            "eligibility_reason": reason,
            "recipient_label": self._notifications.config.recipient_label,
            "request_token": self._notifications.generate_request_token(
                alert["public_alert_id"], session_csrf
            ) if eligible else None,
            "latest_delivery": _safe_delivery(attempts[0]) if attempts else None,
            "recent_deliveries": tuple(_safe_delivery(item) for item in attempts),
        }

    def notify(self, alert_id, token, session_csrf):
        return self._notifications.notify(alert_id, token, session_csrf)

    def status(self):
        if not self._notifications.config.enabled:
            return {
                "notification_attempt_count": 0,
                "successful_notification_count": 0,
                "failed_notification_count": 0,
                "latest_notification_at": None,
            }
        data = self._deliveries.status()
        data["latest_notification_at"] = _iso(data["latest_notification_at"])
        return data
