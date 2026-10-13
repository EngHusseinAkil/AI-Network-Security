import threading
from typing import Protocol

from .models import NotificationProviderResult


class NotificationProvider(Protocol):
    def send(self, message, timeout_seconds): ...
    def health_status(self): ...
    def close(self): ...


class FakeNotificationProvider:
    def __init__(self, outcome="sent"):
        self._outcome = outcome
        self._closed = False
        self._lock = threading.Lock()
        self.deliveries = []

    def send(self, message, timeout_seconds):
        with self._lock:
            if self._closed:
                return NotificationProviderResult("unavailable", "provider_closed")
            self.deliveries.append({
                "notification_id": message.notification_id,
                "alert_id": message.alert_id,
                "status": self._outcome,
            })
        if self._outcome == "sent":
            return NotificationProviderResult("sent", provider_message_reference="fake-delivered")
        if self._outcome == "timeout":
            return NotificationProviderResult("timeout", "provider_timeout")
        return NotificationProviderResult("failed", "provider_failure")

    def health_status(self):
        return "unavailable" if self._closed else "available"

    def close(self):
        self._closed = True


class UnavailableEmailProvider:
    def send(self, message, timeout_seconds):
        return NotificationProviderResult("unavailable", "provider_unavailable")

    def health_status(self):
        return "unavailable"

    def close(self):
        return None
