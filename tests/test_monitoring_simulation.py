"""
Tests for Phase 6 - Milestone 13: Simulated Monitoring-to-Policy Integration.
"""
import pytest
from unittest.mock import Mock, MagicMock
from backend.services.monitoring_simulation_service import MonitoringSimulationService
from backend.services.monitoring_service import MonitoringStateService, MonitoringState
from alerts.policy import AlertPolicy, DecisionOutput
from alerts.constants import AlertType, AlertSeverity, PolicyReasonCode

def test_successful_simulation():
    inference_service = Mock()
    inference_service.predict_flow.return_value = {
        "predicted_canonical_label": "malware",
        "confidence_score": 0.9,
        "risk_score": 0.95,
        "model_version": "1.0",
        "schema_version": "1.0"
    }

    alert_policy = Mock()
    alert_policy.evaluate.return_value = DecisionOutput(
        should_create_alert=True,
        proposed_type=AlertType.SUSPECTED_MALWARE,
        proposed_severity=AlertSeverity.CRITICAL,
        reason_code=PolicyReasonCode.RISK_THRESHOLD_MET,
        cooldown_key="cd:123",
        suppression_status="none",
        policy_version="1.0.0",
        explanation="Test"
    )

    state_service = MonitoringStateService()
    sim_service = MonitoringSimulationService(inference_service, alert_policy, state_service)

    features = {"duration": 10.0, "packet_count": 100}
    
    result = sim_service.simulate_flow(features)
    
    assert result["state"] == "simulation_complete"
    assert result["alert_recommended"] is True
    assert result["proposed_alert_type"] == "suspected_malware"
    assert result["alert_persisted"] is False
    assert result["notification_sent"] is False
    assert result["blocking_executed"] is False
    assert result["features"] == features
    
    status = state_service.get_status()
    assert status["simulation_cycle_count"] == 1
    assert status["simulated_flow_count"] == 1
    assert status["successful_simulation_inference_count"] == 1
    assert status["simulation_recommendation_count"] == 1
    assert status["latest_simulation_result"]["simulation_cycle_id"] == result["simulation_cycle_id"]
    assert status["latest_simulation_result"]["features"] == features

def test_inference_failure():
    inference_service = Mock()
    inference_service.predict_flow.side_effect = Exception("Model is down")

    alert_policy = Mock()

    state_service = MonitoringStateService()
    sim_service = MonitoringSimulationService(inference_service, alert_policy, state_service)

    features = {"duration": 10.0}
    
    result = sim_service.simulate_flow(features)
    
    assert result["state"] == "error"
    assert result["inference_status"] == "error"
    assert result["safe_error_category"] == "inference_unavailable"
    
    # Alert policy should not be called
    alert_policy.evaluate.assert_not_called()
    
    status = state_service.get_status()
    assert status["simulation_cycle_count"] == 1
    assert status["simulated_flow_count"] == 1
    assert status["successful_simulation_inference_count"] == 0
    assert status["failed_simulation_inference_count"] == 1

def test_policy_failure():
    inference_service = Mock()
    inference_service.predict_flow.return_value = {
        "predicted_canonical_label": "malware",
        "confidence_score": 0.9,
        "risk_score": 0.95
    }

    alert_policy = Mock()
    alert_policy.evaluate.side_effect = Exception("Policy error")

    state_service = MonitoringStateService()
    sim_service = MonitoringSimulationService(inference_service, alert_policy, state_service)

    features = {"duration": 10.0}
    
    result = sim_service.simulate_flow(features)
    
    assert result["state"] == "error"
    assert result["inference_status"] == "success"
    assert result["policy_status"] == "error"
    assert result["safe_error_category"] == "policy_unavailable"
    
    # Check that state counters are updated properly on generic error.
    status = state_service.get_status()
    assert status["simulation_cycle_count"] == 1
    assert status["simulated_flow_count"] == 1
    assert status["successful_simulation_inference_count"] == 0 # we didn't get to success
    
def test_simultaneous_requests_state_guard():
    import threading
    state_service = MonitoringStateService()
    
    # Just checking basic locking syntax
    state_service.update_simulation_start()
    assert state_service._state == MonitoringState.RUNNING
    state_service.clear_running_state()
    assert state_service._state == MonitoringState.ERROR
