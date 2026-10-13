from types import SimpleNamespace

from backend.app_factory import create_app


class FakeReadiness:
    def __init__(self, ready):
        self.ready = ready
        self.calls = 0

    def check(self, config):
        self.calls += 1
        return {
            "status": "ready" if self.ready else "not_ready",
            "components": {"database": "ready" if self.ready else "failed"},
            "warnings": (),
        }


def _app(ready):
    service = FakeReadiness(ready)
    dependencies = SimpleNamespace(readiness_service=service)
    app = create_app({"TESTING": True}, dependencies=dependencies)
    return app, service


def test_liveness_has_no_readiness_side_effects():
    app, service = _app(False)
    response = app.test_client().get("/health/live")
    assert response.status_code == 200
    assert response.get_json() == {"status": "alive"}
    assert service.calls == 0


def test_readiness_maps_ready_and_failure_without_details():
    ready_app, ready_service = _app(True)
    assert ready_app.test_client().get("/health/ready").status_code == 200
    failed_app, failed_service = _app(False)
    response = failed_app.test_client().get("/health/ready")
    assert response.status_code == 503
    body = response.get_data(as_text=True)
    assert "secret" not in body.casefold()
    assert ready_service.calls == failed_service.calls == 1
