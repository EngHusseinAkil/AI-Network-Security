import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy.exc import IntegrityError
import json
from unittest.mock import patch, MagicMock

from alerts.models import Alert as DomainAlert
from alerts.constants import AlertType, AlertSeverity, AlertStatus
from database.models.alert import Alert as PersistenceAlert
from database.repositories.alert_repository import AlertRepository
from backend.services.alert_persistence_service import AlertPersistenceService
from utils.time_utils import get_current_utc_time
from utils.exceptions import ApplicationError, ConflictError, NotFoundError

@pytest.fixture
def mock_session_scope(db_session):
    from contextlib import contextmanager
    @contextmanager
    def _mock_scope():
        try:
            yield db_session
            db_session.commit()
        except Exception:
            db_session.rollback()
            raise

    with patch('backend.services.alert_persistence_service.session_scope', _mock_scope):
        yield db_session

def test_alert_persistence_mapping(mock_session_scope):
    db_session = mock_session_scope
    repo = AlertRepository(db_session)
    service = AlertPersistenceService()

    now = get_current_utc_time()

    domain_alert = DomainAlert(
        alert_id="pub-123",
        type=AlertType.SUSPECTED_DDOS,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        title="DDoS Detected",
        description="High volume",
        source_category="network",
        predicted_canonical_label="ddos",
        confidence_score=0.9,
        risk_score=0.95,
        model_version="v1",
        schema_version="1",
        created_at=now,
        deduplication_key="dedup-123",
        safe_metadata={"src_ip": "hash_abcd"}
    )

    # Store alert
    result = service.store_alert(domain_alert, "v1_policy", "REPEATED_ACTIVITY")
    assert result['public_alert_id'] == "pub-123"
    assert result['title'] == "DDoS Detected"
    assert result['risk_score'] == 0.95
    assert result['policy_version'] == "v1_policy"

    # Fetch from repo to check exact types
    persisted = repo.get_by_public_id("pub-123")
    assert persisted is not None
    assert persisted.public_alert_id == "pub-123"
    assert persisted.confidence_score == 0.9
    assert json.loads(persisted.safe_metadata) == {"src_ip": "hash_abcd"}

def test_duplicate_public_id(mock_session_scope):
    db_session = mock_session_scope
    repo = AlertRepository(db_session)
    service = AlertPersistenceService()
    now = get_current_utc_time()

    domain_alert = DomainAlert(
        alert_id="pub-456",
        type=AlertType.SUSPECTED_PORT_SCAN,
        severity=AlertSeverity.LOW,
        status=AlertStatus.NEW,
        title="Scan",
        description="Scan",
        source_category="network",
        predicted_canonical_label="port_scan",
        confidence_score=0.9,
        risk_score=0.5,
        model_version="v1",
        schema_version="1",
        created_at=now,
        deduplication_key="dedup-456"
    )

    service.store_alert(domain_alert, "v1", "TEST")

    # Try storing again with same public ID (violates unique constraint)
    with pytest.raises(ApplicationError, match="integrity constraint"):
        service.store_alert(domain_alert, "v1", "TEST")

def test_model_constraints(db_session):
    # Test confidence_score constraint
    alert = PersistenceAlert(
        public_alert_id="test-1",
        alert_type="suspected_ddos",
        severity="high",
        status="new",
        title="Test",
        description="Test",
        source_category="test",
        confidence_score=1.5, # Invalid
        risk_score=0.5,
        deduplication_key="123",
        occurrence_count=1,
    )
    db_session.add(alert)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Test occurrence count
    alert2 = PersistenceAlert(
        public_alert_id="test-2",
        alert_type="suspected_ddos",
        severity="high",
        status="new",
        title="Test",
        description="Test",
        source_category="test",
        confidence_score=0.5,
        risk_score=0.5,
        deduplication_key="123",
        occurrence_count=0, # Invalid
    )
    db_session.add(alert2)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Test enum values
    alert3 = PersistenceAlert(
        public_alert_id="test-3",
        alert_type="suspected_ddos",
        severity="extreme", # Invalid
        status="new",
        title="Test",
        description="Test",
        source_category="test",
        confidence_score=0.5,
        risk_score=0.5,
        deduplication_key="123",
        occurrence_count=1,
    )
    db_session.add(alert3)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

def test_repository_pagination_and_filtering(db_session):
    repo = AlertRepository(db_session)
    now = get_current_utc_time()

    for i in range(5):
        a = PersistenceAlert(
            public_alert_id=f"alert-{i}",
            alert_type="suspected_ddos" if i % 2 == 0 else "suspected_port_scan",
            severity="high" if i < 3 else "low",
            status="new",
            title=f"Alert {i}",
            description="Test",
            source_category="network",
            confidence_score=0.9,
            risk_score=0.9,
            deduplication_key=f"dedup-{i}",
            created_at=now + timedelta(seconds=i)
        )
        db_session.add(a)
    db_session.commit()

    # Test Pagination
    alerts = repo.get_alerts(page=1, page_size=2)
    assert len(alerts) == 2

    # Test Filtering
    high_alerts = repo.get_alerts(page=1, page_size=10, severity="high")
    assert len(high_alerts) == 3

    ddos_alerts = repo.get_alerts(page=1, page_size=10, alert_type="suspected_ddos")
    assert len(ddos_alerts) == 3

    # Test Ordering
    assert alerts[0].public_alert_id == "alert-4"
    assert alerts[1].public_alert_id == "alert-3"

def test_transition_alert_success(mock_session_scope):
    db_session = mock_session_scope
    repo = AlertRepository(db_session)
    service = AlertPersistenceService()
    now = get_current_utc_time()

    domain_alert = DomainAlert(
        alert_id="trans-123",
        type=AlertType.SUSPECTED_DDOS,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        title="DDoS Detected",
        description="High volume",
        source_category="network",
        predicted_canonical_label="ddos",
        confidence_score=0.9,
        risk_score=0.95,
        model_version="v1",
        schema_version="1",
        created_at=now,
        deduplication_key="dedup-trans",
        version=1
    )

    service.store_alert(domain_alert, "v1_policy", "REASON")

    # Transition to acknowledged
    ts = (now + timedelta(seconds=1)).isoformat()
    res = service.transition_alert("trans-123", "acknowledged", ts, 1)

    assert res["status"] == "acknowledged"
    assert res["version"] == 2
    assert res["acknowledged_at"] is not None

def test_transition_alert_stale_update(mock_session_scope):
    db_session = mock_session_scope
    service = AlertPersistenceService()
    now = get_current_utc_time()

    domain_alert = DomainAlert(
        alert_id="stale-123",
        type=AlertType.SUSPECTED_DDOS,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        title="DDoS",
        description="DDoS",
        source_category="network",
        predicted_canonical_label="ddos",
        confidence_score=0.9,
        risk_score=0.9,
        model_version="v1",
        schema_version="1",
        created_at=now,
        deduplication_key="dedup-stale",
        version=1
    )

    service.store_alert(domain_alert, "v1", "REASON")

    ts = (now + timedelta(seconds=1)).isoformat()
    # Wrong expected version
    with pytest.raises(ConflictError, match="modified"):
        service.transition_alert("stale-123", "acknowledged", ts, 99)

def test_transition_alert_invalid_transition(mock_session_scope):
    db_session = mock_session_scope
    service = AlertPersistenceService()
    now = get_current_utc_time()

    domain_alert = DomainAlert(
        alert_id="invalid-123",
        type=AlertType.SUSPECTED_DDOS,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        title="DDoS",
        description="DDoS",
        source_category="network",
        predicted_canonical_label="ddos",
        confidence_score=0.9,
        risk_score=0.9,
        model_version="v1",
        schema_version="1",
        created_at=now,
        deduplication_key="dedup-invalid",
        version=1
    )

    service.store_alert(domain_alert, "v1", "REASON")
    ts = (now + timedelta(seconds=1)).isoformat()
    service.transition_alert("invalid-123", "dismissed", ts, 1)

    ts2 = (now + timedelta(seconds=2)).isoformat()
    # Cannot transition from dismissed to acknowledged
    with pytest.raises(ConflictError, match="Invalid transition"):
        service.transition_alert("invalid-123", "acknowledged", ts2, 2)
