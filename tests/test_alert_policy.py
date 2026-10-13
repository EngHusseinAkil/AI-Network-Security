import pytest
from datetime import datetime, timezone, timedelta

from alerts.constants import AlertType, AlertSeverity, PolicyReasonCode
from alerts.exceptions import PolicyConfigurationError, AlertValidationError
from alerts.policy import DecisionInput, ThresholdConfig, AlertPolicy, is_in_cooldown
from utils.time_utils import get_current_utc_time

def test_threshold_config_validation():
    with pytest.raises(PolicyConfigurationError, match="ordered"):
        ThresholdConfig(min_risk=0.9, elevated_risk=0.8)

    with pytest.raises(PolicyConfigurationError, match="between 0.0 and 1.0"):
        ThresholdConfig(min_confidence=1.5)

def test_benign_policy():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="benign",
        confidence_score=0.9,
        risk_score=0.95, # high risk but benign label
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=1,
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is False
    assert result.reason_code == PolicyReasonCode.BENIGN_PREDICTION

def test_unknown_policy():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="unknown",
        confidence_score=0.9,
        risk_score=0.95,
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=1,
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is True
    assert result.proposed_type == AlertType.SUSPICIOUS_UNKNOWN
    # Unknown caps out at MEDIUM, even with 0.95 risk
    assert result.proposed_severity == AlertSeverity.MEDIUM
    assert result.reason_code == PolicyReasonCode.UNKNOWN_UNCERTAINTY

def test_unknown_policy_below_threshold():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="unknown",
        confidence_score=0.5, # Below default 0.7
        risk_score=0.5, # Below default 0.6
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=1,
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is False
    assert result.reason_code == PolicyReasonCode.BELOW_THRESHOLD

def test_threat_policy_below_threshold():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="malware",
        confidence_score=0.9,
        risk_score=0.5, # Below 0.6
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=1,
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is False
    assert result.reason_code == PolicyReasonCode.BELOW_THRESHOLD

def test_threat_policy_qualifying_low():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="botnet",
        confidence_score=0.8,
        risk_score=0.7, # 0.6 <= x < 0.8 -> LOW
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=1,
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is True
    assert result.proposed_type == AlertType.SUSPECTED_BOTNET
    assert result.proposed_severity == AlertSeverity.LOW

def test_threat_policy_qualifying_medium():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="port_scan",
        confidence_score=0.8,
        risk_score=0.85, # 0.8 <= x < 0.95 -> MEDIUM
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=1,
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is True
    assert result.proposed_type == AlertType.SUSPECTED_PORT_SCAN
    assert result.proposed_severity == AlertSeverity.MEDIUM

def test_threat_policy_qualifying_critical():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="ddos",
        confidence_score=0.9,
        risk_score=0.99, # >= 0.95 and type is DDoS -> CRITICAL
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=1,
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is True
    assert result.proposed_type == AlertType.SUSPECTED_DDOS
    assert result.proposed_severity == AlertSeverity.CRITICAL

def test_threat_policy_repeated_activity():
    policy = AlertPolicy()
    input_data = DecisionInput(
        predicted_canonical_label="botnet",
        confidence_score=0.8,
        risk_score=0.7, # Normal severity would be LOW
        model_version="v1.0",
        schema_version="1.0",
        source_category="network",
        occurrence_count=10, # >= 5 repeated count
        observation_window_seconds=60,
        current_monitoring_state="running",
        pseudonymous_source_key="pseudo-1"
    )
    result = policy.evaluate(input_data)
    assert result.should_create_alert is True
    assert result.proposed_severity == AlertSeverity.HIGH
    assert result.reason_code == PolicyReasonCode.REPEATED_ACTIVITY

def test_cooldown_logic():
    now = get_current_utc_time()

    # Active cooldown
    assert is_in_cooldown(now, now + timedelta(seconds=10), 300) is True

    # Expired cooldown
    assert is_in_cooldown(now, now + timedelta(seconds=301), 300) is False

    # No last alert
    assert is_in_cooldown(None, now, 300) is False

    # Clock skew (current before last) - fails safe
    assert is_in_cooldown(now, now - timedelta(seconds=10), 300) is False

def test_cooldown_naive_rejection():
    now = get_current_utc_time()
    naive = datetime.now()

    with pytest.raises(AlertValidationError):
        is_in_cooldown(naive, now, 300)

    with pytest.raises(AlertValidationError):
        is_in_cooldown(now, naive, 300)
