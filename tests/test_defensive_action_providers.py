from defense.models import DefensiveTarget
from defense.providers import FakeDefensiveActionProvider


def test_fake_apply_remove_failure_timeout_and_close():
    target = DefensiveTarget("ref", "demo", "masked", "native")
    for outcome in ("applied", "failed", "timeout"):
        provider = FakeDefensiveActionProvider(outcome)
        assert provider.apply_temporary_deny(target, 900).status == outcome
    provider = FakeDefensiveActionProvider()
    assert provider.remove_temporary_deny(target, "fake:ref").status == "applied"
    provider.close(); provider.close()
    assert provider.status() == "unavailable"
