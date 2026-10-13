from concurrent.futures import ThreadPoolExecutor

from backend.services.live_flow_alert_creation_service import LiveFlowAlertCreationService
from tests.live_flow_alert_test_support import MemoryPersistence, retained_state


def test_sequential_replay_resolves_same_durable_alert():
    state, persistence = retained_state(), MemoryPersistence()
    service = LiveFlowAlertCreationService(
        "secret", state, persistence, "live-flow-evaluation-v1"
    )
    token = service.generate_token("evaluation-1", "csrf")
    first = service.create_alert("evaluation-1", token, "csrf")
    second = service.create_alert("evaluation-1", token, "csrf")
    assert first[0] == second[0] and second[1]
    assert len(persistence.stored) == 1


def test_concurrent_replay_creates_one_alert():
    state, persistence = retained_state(), MemoryPersistence()
    service = LiveFlowAlertCreationService(
        "secret", state, persistence, "live-flow-evaluation-v1"
    )
    token = service.generate_token("evaluation-1", "csrf")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda _: service.create_alert("evaluation-1", token, "csrf"), range(2)
        ))
    assert results[0][0] == results[1][0]
    assert len(persistence.stored) == 1


def test_process_local_link_loss_does_not_duplicate():
    persistence = MemoryPersistence()
    first_state = retained_state()
    first = LiveFlowAlertCreationService(
        "secret", first_state, persistence, "live-flow-evaluation-v1"
    )
    token = first.generate_token("evaluation-1", "csrf")
    alert_id, _ = first.create_alert("evaluation-1", token, "csrf")
    replacement = LiveFlowAlertCreationService(
        "secret", retained_state(), persistence, "live-flow-evaluation-v1"
    )
    replay_id, replayed = replacement.create_alert("evaluation-1", token, "csrf")
    assert replayed and replay_id == alert_id and len(persistence.stored) == 1
