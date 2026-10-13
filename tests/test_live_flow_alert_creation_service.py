import hashlib
import pytest

from backend.services.live_flow_alert_creation_service import (
    LiveFlowAlertConflict, LiveFlowAlertCreationService,
)
from tests.live_flow_alert_test_support import (
    MemoryPersistence, eligible_record, retained_state,
)


def test_alert_fields_are_mapped_only_from_retained_evaluation():
    state = retained_state()
    persistence = MemoryPersistence()
    service = LiveFlowAlertCreationService(
        "secret", state, persistence, "live-flow-evaluation-v1"
    )
    alert_id, replayed = service.create_alert(
        "evaluation-1", service.generate_token("evaluation-1", "csrf"), "csrf"
    )
    alert, policy, reason = persistence.stored[0]
    assert not replayed and alert.alert_id == alert_id
    assert alert.source_category == "live_metadata_flow"
    assert alert.type.value == "suspected_ddos" and alert.severity.value == "high"
    assert alert.safe_metadata == {
        "evaluation_id": "evaluation-1", "occurrence_count": 1,
        "policy_version": "policy-v1", "reason_code": "risk_threshold_met",
    }
    assert policy == "policy-v1" and reason == "risk_threshold_met"
    assert "token" not in str(alert.safe_metadata)
    linked = state.get_record("evaluation-1")
    assert linked.alert_persisted and linked.persisted_alert_id == alert_id


def test_ineligible_record_conflicts():
    state = retained_state(eligible_record(alert_recommended=False))
    service = LiveFlowAlertCreationService(
        "secret", state, MemoryPersistence(), "live-flow-evaluation-v1"
    )
    assert service.generate_token("evaluation-1", "csrf") is None
    record = state.get_record("evaluation-1")
    token = service._serializer.dumps({
        "evaluation_id": record.evaluation_id,
        "evaluation_schema_version": record.evaluation_schema_version,
        "flow_id": record.flow_id,
        "model_version": record.model_version,
        "policy_version": record.policy_version,
        "purpose": "live-flow-alert-recommendation-v1",
        "session_digest": hashlib.sha256(b"csrf").hexdigest(),
    })
    with pytest.raises(LiveFlowAlertConflict):
        service.create_alert("evaluation-1", token, "csrf")
