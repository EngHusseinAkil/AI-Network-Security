from backend.services.shutdown_service import ShutdownCoordinator


class Resource:
    def __init__(self):
        self.calls = 0

    def close(self):
        self.calls += 1

    def shutdown(self):
        self.calls += 1


def test_shutdown_is_idempotent_and_closes_every_resource():
    capture, notification, defensive, database = (
        Resource(), Resource(), Resource(), Resource()
    )
    coordinator = ShutdownCoordinator(
        capture, notification, defensive, database.close
    )
    assert coordinator.shutdown()
    assert coordinator.shutdown()
    assert [item.calls for item in (capture, notification, defensive, database)] == [
        1, 1, 1, 1,
    ]


def test_shutdown_is_safe_when_resources_fail():
    class Failure(Resource):
        def close(self):
            raise RuntimeError("safe failure")
    coordinator = ShutdownCoordinator(Resource(), Failure(), Failure(), Failure().close)
    assert coordinator.shutdown()
