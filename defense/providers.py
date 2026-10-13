import threading
from typing import Protocol

from .models import DefensiveProviderResult


class DefensiveActionProvider(Protocol):
    def apply_temporary_deny(self, target, duration_seconds): ...
    def remove_temporary_deny(self, target, provider_reference): ...
    def status(self): ...
    def close(self): ...


class FakeDefensiveActionProvider:
    def __init__(self, outcome="applied", remove_outcome="removed"):
        self.outcome = outcome
        self.remove_outcome = remove_outcome
        self.calls = []
        self._closed = False
        self._lock = threading.Lock()

    def apply_temporary_deny(self, target, duration_seconds):
        if self._closed:
            return DefensiveProviderResult("unavailable", "provider_unavailable")
        with self._lock:
            self.calls.append(("apply", target.reference_id, duration_seconds))
        if self.outcome == "applied":
            return DefensiveProviderResult(
                "applied", provider_reference=f"fake:{target.reference_id}"
            )
        if self.outcome == "timeout":
            return DefensiveProviderResult("timeout", "provider_timeout")
        return DefensiveProviderResult("failed", "provider_failure")

    def remove_temporary_deny(self, target, provider_reference):
        if self._closed:
            return DefensiveProviderResult("unavailable", "provider_unavailable")
        with self._lock:
            self.calls.append(("remove", target.reference_id, provider_reference))
        if self.remove_outcome == "removed":
            return DefensiveProviderResult("applied", provider_reference=provider_reference)
        if self.remove_outcome == "timeout":
            return DefensiveProviderResult("timeout", "provider_timeout")
        return DefensiveProviderResult("failed", "provider_failure")

    def status(self):
        return "unavailable" if self._closed else "available"

    def close(self):
        self._closed = True


class UnavailableDefensiveActionProvider:
    def apply_temporary_deny(self, target, duration_seconds):
        return DefensiveProviderResult("unavailable", "provider_unavailable")

    def remove_temporary_deny(self, target, provider_reference):
        return DefensiveProviderResult("unavailable", "provider_unavailable")

    def status(self):
        return "unavailable"

    def close(self):
        return None
