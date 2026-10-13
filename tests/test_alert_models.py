import pytest
from datetime import datetime, timezone, timedelta
from dataclasses import FrozenInstanceError

from alerts.models import Alert
from alerts.constants import AlertType, AlertSeverity, AlertStatus
from alerts.exceptions import AlertValidationError
from utils.time_utils import get_current_utc_time

def test_alert_creation_success():
    """Test valid alert object creation."""
    now = get_current_utc_time()
    alert = Alert(
        alert_id="test-123",
        type=AlertType.SUSPECTED_DDOS,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        title="DDoS Detected",
        description="High volume traffic",
        source_category="network",
        predicted_canonical_label="ddos",
        confidence_score=0.95,
        risk_score=0.9,
        model_version="v1.0",
        schema_version="1.0",
        created_at=now,
        deduplication_key="abc123hash"
    )
    assert alert.type == AlertType.SUSPECTED_DDOS
    assert alert.status == AlertStatus.NEW

def test_alert_immutability():
    """Test alert cannot be mutated directly."""
    now = get_current_utc_time()
    alert = Alert(
        alert_id="test-123",
        type=AlertType.SUSPECTED_DDOS,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        title="DDoS Detected",
        description="High volume traffic",
        source_category="network",
        predicted_canonical_label="ddos",
        confidence_score=0.95,
        risk_score=0.9,
        model_version="v1.0",
        schema_version="1.0",
        created_at=now,
        deduplication_key="abc123hash"
    )
    with pytest.raises(FrozenInstanceError):
        alert.status = AlertStatus.ACKNOWLEDGED

def test_invalid_alert_type():
    with pytest.raises(AlertValidationError, match="Invalid alert type"):
        Alert(
            alert_id="test-123",
            type="invalid_type",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.NEW,
            title="Title",
            description="Desc",
            source_category="net",
            predicted_canonical_label="ddos",
            confidence_score=0.9,
            risk_score=0.9,
            model_version="v1",
            schema_version="1",
            created_at=get_current_utc_time(),
            deduplication_key="abc"
        )

def test_invalid_alert_severity():
    with pytest.raises(AlertValidationError, match="Invalid alert severity"):
        Alert(
            alert_id="test-123",
            type=AlertType.SUSPECTED_DDOS,
            severity="extreme",
            status=AlertStatus.NEW,
            title="Title",
            description="Desc",
            source_category="net",
            predicted_canonical_label="ddos",
            confidence_score=0.9,
            risk_score=0.9,
            model_version="v1",
            schema_version="1",
            created_at=get_current_utc_time(),
            deduplication_key="abc"
        )

def test_invalid_alert_status():
    with pytest.raises(AlertValidationError, match="Invalid alert status"):
        Alert(
            alert_id="test-123",
            type=AlertType.SUSPECTED_DDOS,
            severity=AlertSeverity.HIGH,
            status="pending",
            title="Title",
            description="Desc",
            source_category="net",
            predicted_canonical_label="ddos",
            confidence_score=0.9,
            risk_score=0.9,
            model_version="v1",
            schema_version="1",
            created_at=get_current_utc_time(),
            deduplication_key="abc"
        )

def test_invalid_scores():
    now = get_current_utc_time()
    with pytest.raises(AlertValidationError, match="confidence_score must be between 0.0 and 1.0"):
        Alert("1", AlertType.SUSPECTED_DDOS, AlertSeverity.HIGH, AlertStatus.NEW, "T", "D", "S", "ddos", 1.5, 0.5, "v1", "1", now, deduplication_key="k")

    with pytest.raises(AlertValidationError, match="risk_score must be between 0.0 and 1.0"):
        Alert("1", AlertType.SUSPECTED_DDOS, AlertSeverity.HIGH, AlertStatus.NEW, "T", "D", "S", "ddos", 0.5, -0.1, "v1", "1", now, deduplication_key="k")

def test_valid_lifecycle_transition():
    now = get_current_utc_time()
    alert = Alert(
        alert_id="1", type=AlertType.SUSPECTED_DDOS, severity=AlertSeverity.HIGH, status=AlertStatus.NEW,
        title="T", description="D", source_category="S", predicted_canonical_label="ddos",
        confidence_score=0.9, risk_score=0.9, model_version="v1", schema_version="1",
        created_at=now, deduplication_key="k"
    )

    ack_time = now + timedelta(minutes=5)
    alert2 = alert.transition_to(AlertStatus.ACKNOWLEDGED, ack_time)
    assert alert2.status == AlertStatus.ACKNOWLEDGED
    assert alert2.acknowledged_at == ack_time

    res_time = ack_time + timedelta(minutes=5)
    alert3 = alert2.transition_to(AlertStatus.RESOLVED, res_time)
    assert alert3.status == AlertStatus.RESOLVED
    assert alert3.resolved_at == res_time

def test_invalid_lifecycle_transition():
    now = get_current_utc_time()
    alert = Alert(
        alert_id="1", type=AlertType.SUSPECTED_DDOS, severity=AlertSeverity.HIGH, status=AlertStatus.NEW,
        title="T", description="D", source_category="S", predicted_canonical_label="ddos",
        confidence_score=0.9, risk_score=0.9, model_version="v1", schema_version="1",
        created_at=now, deduplication_key="k"
    )

    ack_time = now + timedelta(minutes=5)
    alert2 = alert.transition_to(AlertStatus.ACKNOWLEDGED, ack_time)

    res_time = ack_time + timedelta(minutes=5)
    alert3 = alert2.transition_to(AlertStatus.RESOLVED, res_time)

    # Resolved -> New should fail
    with pytest.raises(AlertValidationError, match="Invalid transition from resolved to new"):
        alert3.transition_to(AlertStatus.NEW, res_time + timedelta(minutes=5))

def test_timestamp_consistency():
    now = get_current_utc_time()
    alert = Alert(
        alert_id="1", type=AlertType.SUSPECTED_DDOS, severity=AlertSeverity.HIGH, status=AlertStatus.NEW,
        title="T", description="D", source_category="S", predicted_canonical_label="ddos",
        confidence_score=0.9, risk_score=0.9, model_version="v1", schema_version="1",
        created_at=now, deduplication_key="k"
    )

    # Transition with earlier timestamp should fail against created_at
    past_time = now - timedelta(minutes=5)
    with pytest.raises(AlertValidationError, match="Transition timestamp cannot be earlier than created_at"):
        alert.transition_to(AlertStatus.ACKNOWLEDGED, past_time)

    # Transition successfully to ACKNOWLEDGED
    ack_time = now + timedelta(minutes=5)
    alert2 = alert.transition_to(AlertStatus.ACKNOWLEDGED, ack_time)

    # Transition to RESOLVED with a timestamp before ACKNOWLEDGED
    res_past_time = ack_time - timedelta(minutes=1)
    with pytest.raises(AlertValidationError, match="Transition timestamp cannot be earlier than previous state changes"):
        alert2.transition_to(AlertStatus.RESOLVED, res_past_time)

def test_naive_timestamp_rejection():
    now = datetime.now() # Naive
    with pytest.raises(AlertValidationError, match="must be timezone-aware"):
        Alert(
            alert_id="1", type=AlertType.SUSPECTED_DDOS, severity=AlertSeverity.HIGH, status=AlertStatus.NEW,
            title="T", description="D", source_category="S", predicted_canonical_label="ddos",
            confidence_score=0.9, risk_score=0.9, model_version="v1", schema_version="1",
            created_at=now, deduplication_key="k"
        )

def test_deduplication_key_generation():
    key = Alert.generate_duplicate_key(AlertType.SUSPECTED_DDOS, "pseudo-123", "v1.0", "2024-01-01T00:00:00Z")
    assert isinstance(key, str)
    assert len(key) == 64  # SHA-256 hex length

    key2 = Alert.generate_duplicate_key(AlertType.SUSPECTED_DDOS, "pseudo-123", "v1.0", "2024-01-01T00:00:00Z")
    assert key == key2 # deterministic
