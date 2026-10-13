def _iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def _safe_action(item, remove_token=None):
    return {
        "action_id": item["action_id"],
        "action_type": item["action_type"],
        "target_category": item["target_category"],
        "masked_target_label": item["masked_target_label"],
        "provider_category": item["provider_category"],
        "requested_at": _iso(item["requested_at"]),
        "applied_at": _iso(item["applied_at"]),
        "expires_at": _iso(item["expires_at"]),
        "removed_at": _iso(item["removed_at"]),
        "status": item["status"],
        "safe_error_category": item["safe_error_category"],
        "duration_seconds": item["duration_seconds"],
        "remove_token": remove_token,
    }


class DashboardDefensiveActionService:
    def __init__(self, service, persistence):
        self._service = service
        self._persistence = persistence

    def presentation(self, alert, session_csrf):
        recommendation = self._service.recommendation(alert)
        actions = (
            self._persistence.for_alert(alert["public_alert_id"])
            if self._service.config.enabled else ()
        )
        presented = tuple(
            _safe_action(
                item,
                self._service.generate_remove_token(item, session_csrf)
                if item["status"] == "applied" else None,
            )
            for item in actions
        )
        return {
            "enabled": self._service.config.enabled,
            "provider": self._service.config.provider,
            "recommendation": recommendation,
            "apply_token": self._service.generate_apply_token(
                alert, session_csrf
            ) if recommendation.eligible else None,
            "recent_actions": presented,
            "latest_action": presented[0] if presented else None,
        }

    def apply(self, alert_id, token, session_csrf):
        return self._service.apply(alert_id, token, session_csrf)

    def remove(self, alert_id, action_id, token, session_csrf):
        return self._service.remove(alert_id, action_id, token, session_csrf)

    def status(self):
        if not self._service.config.enabled:
            return {
                "pending_defensive_action_count": 0,
                "active_temporary_action_count": 0,
                "failed_defensive_action_count": 0,
                "expired_defensive_action_count": 0,
                "removed_defensive_action_count": 0,
                "latest_defensive_action_at": None,
            }
        data = self._persistence.status()
        data["latest_defensive_action_at"] = _iso(data["latest_defensive_action_at"])
        return data
