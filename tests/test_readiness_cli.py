from types import SimpleNamespace

from backend.app_factory import create_app


class Readiness:
    def __init__(self, status):
        self.status = status

    def check(self, config):
        return {
            "status": self.status,
            "components": {"database": "ready" if self.status == "ready" else "failed"},
            "warnings": (),
        }


def test_readiness_cli_exit_codes_and_safe_output():
    ready = create_app(
        {"TESTING": True},
        dependencies=SimpleNamespace(readiness_service=Readiness("ready")),
    )
    success = ready.test_cli_runner().invoke(args=["system", "readiness"])
    assert success.exit_code == 0
    assert "status: ready" in success.output
    failed = create_app(
        {"TESTING": True},
        dependencies=SimpleNamespace(readiness_service=Readiness("not_ready")),
    )
    failure = failed.test_cli_runner().invoke(args=["system", "readiness"])
    assert failure.exit_code == 1
    assert "secret" not in failure.output.casefold()
