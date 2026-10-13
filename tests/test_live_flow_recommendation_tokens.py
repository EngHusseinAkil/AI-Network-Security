from itsdangerous import URLSafeTimedSerializer
import pytest

from backend.services.live_flow_alert_creation_service import (
    LiveFlowAlertCreationService, LiveFlowAlertError, TOKEN_SALT,
)
from tests.live_flow_alert_test_support import (
    MemoryPersistence, eligible_record, retained_state,
)


@pytest.mark.parametrize("changes", [
    {"feature_compatible": False},
    {"inference_status": "failed"},
    {"policy_status": "failed"},
    {"alert_recommended": False},
])
def test_token_only_generated_for_eligible_record(changes):
    state = retained_state(eligible_record(**changes))
    service = LiveFlowAlertCreationService(
        "secret", state, MemoryPersistence(), "live-flow-evaluation-v1"
    )
    assert service.generate_token("evaluation-1", "csrf") is None


def test_token_is_session_bound_and_purpose_separated():
    state = retained_state()
    service = LiveFlowAlertCreationService(
        "secret", state, MemoryPersistence(), "live-flow-evaluation-v1"
    )
    token = service.generate_token("evaluation-1", "csrf")
    with pytest.raises(LiveFlowAlertError):
        service.create_alert("evaluation-1", token, "other")
    simulation = URLSafeTimedSerializer(
        "secret", salt="alert-recommendation"
    ).dumps({"purpose": "create_alert", "evaluation_id": "evaluation-1"})
    with pytest.raises(LiveFlowAlertError):
        service.create_alert("evaluation-1", simulation, "csrf")


def test_payload_tampering_and_route_mismatch_rejected():
    state = retained_state()
    service = LiveFlowAlertCreationService(
        "secret", state, MemoryPersistence(), "live-flow-evaluation-v1"
    )
    token = service.generate_token("evaluation-1", "csrf")
    with pytest.raises(LiveFlowAlertError):
        service.create_alert("other", token, "csrf")
    with pytest.raises(LiveFlowAlertError):
        service.create_alert("evaluation-1", token + "x", "csrf")
