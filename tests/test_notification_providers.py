from tests.alert_notification_test_support import service


def test_fake_provider_success_failure_timeout_and_close():
    for outcome in ("sent", "failed", "timeout"):
        svc, provider, _ = service(outcome)
        token = svc.generate_request_token("alert-1", "csrf")
        try:
            svc.notify("alert-1", token, "csrf")
        except Exception:
            pass
        assert provider.deliveries[0]["status"] == outcome
        provider.close()
        provider.close()
        assert provider.health_status() == "unavailable"
