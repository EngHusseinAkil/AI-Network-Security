from backend.services.runtime_capability_service import RuntimeCapabilityService


def test_runtime_inventory_makes_process_local_state_explicit():
    items = RuntimeCapabilityService().inspect({
        "WEB_WORKER_COUNT": 2, "CAPTURE_ENABLED": False,
    })
    values = {item.name: item for item in items}
    assert values["flow_aggregation"].classification == "worker_local_reconstructable"
    assert values["evaluation_history"].classification == "worker_local_reconstructable"
    assert values["durable_action_idempotency"].classification == "database_shared"


def test_capture_requires_single_owner_when_enabled():
    service = RuntimeCapabilityService()
    multi = service.inspect({"WEB_WORKER_COUNT": 2, "CAPTURE_ENABLED": True})
    single = service.inspect({"WEB_WORKER_COUNT": 1, "CAPTURE_ENABLED": True})
    assert not multi[1].available
    assert single[1].available
