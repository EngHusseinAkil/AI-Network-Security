"""
Tests for AlertRepository covering the behaviors originally tested in the
Phase 2 version of this file, updated for the Phase 6 alert model schema.

Original file was deleted during Phase 6 development because the old Alert
model used fields (message, alert_type="intrusion") that no longer exist.
These tests preserve every repository behavior from the original:
  * query_by_status
  * query_by_severity
  * retrieve_unresolved_alerts
  * get_by_public_id
  * get_by_deduplication_key
  * get_alerts (pagination + filtering)
  * count_alerts
"""
import pytest
from database.models.alert import Alert
from database.repositories.alert_repository import AlertRepository


def _make_alert(public_id, alert_type, severity, status, dedup_key):
    """Helper: build a minimal valid PersistenceAlert row."""
    return Alert(
        public_alert_id=public_id,
        alert_type=alert_type,
        severity=severity,
        status=status,
        title=f"Alert {public_id}",
        description="Test alert",
        source_category="network",
        confidence_score=0.9,
        risk_score=0.8,
        deduplication_key=dedup_key,
        occurrence_count=1,
        version=1,
    )


def test_alert_repository_query_by_status(db_session):
    """query_by_status returns only alerts matching the requested status."""
    repo = AlertRepository(db_session)

    db_session.add(_make_alert("r-1", "suspected_ddos",    "high",   "new",          "dk-r1"))
    db_session.add(_make_alert("r-2", "suspected_malware", "critical", "acknowledged", "dk-r2"))
    db_session.add(_make_alert("r-3", "suspected_ddos",    "medium", "new",           "dk-r3"))
    db_session.commit()

    new_alerts = repo.query_by_status("new")
    assert len(new_alerts) == 2
    statuses = {a.status for a in new_alerts}
    assert statuses == {"new"}

    ack_alerts = repo.query_by_status("acknowledged")
    assert len(ack_alerts) == 1
    assert ack_alerts[0].public_alert_id == "r-2"


def test_alert_repository_query_by_severity(db_session):
    """query_by_severity returns only alerts matching the requested severity."""
    repo = AlertRepository(db_session)

    db_session.add(_make_alert("s-1", "suspected_ddos",   "critical", "new",      "dk-s1"))
    db_session.add(_make_alert("s-2", "suspected_malware", "high",    "resolved", "dk-s2"))
    db_session.add(_make_alert("s-3", "suspected_ddos",   "medium",  "new",      "dk-s3"))
    db_session.commit()

    crit = repo.query_by_severity("critical")
    assert len(crit) == 1
    assert crit[0].public_alert_id == "s-1"

    high = repo.query_by_severity("high")
    assert len(high) == 1
    assert high[0].status == "resolved"


def test_alert_repository_retrieve_unresolved(db_session):
    """retrieve_unresolved_alerts returns only new / open statuses (not resolved/dismissed)."""
    repo = AlertRepository(db_session)

    db_session.add(_make_alert("u-1", "suspected_ddos",     "high",     "new",      "dk-u1"))
    db_session.add(_make_alert("u-2", "suspected_malware",  "critical", "resolved", "dk-u2"))
    db_session.add(_make_alert("u-3", "suspected_port_scan","medium",   "dismissed","dk-u3"))
    db_session.commit()

    unresolved = repo.retrieve_unresolved_alerts()
    # Only "new" (not "resolved" or "dismissed") should be returned
    assert len(unresolved) == 1
    assert unresolved[0].public_alert_id == "u-1"


def test_alert_repository_get_by_public_id(db_session):
    """get_by_public_id returns the correct alert or None."""
    repo = AlertRepository(db_session)

    db_session.add(_make_alert("pub-abc", "suspected_ddos", "high", "new", "dk-pub-abc"))
    db_session.commit()

    found = repo.get_by_public_id("pub-abc")
    assert found is not None
    assert found.public_alert_id == "pub-abc"

    not_found = repo.get_by_public_id("does-not-exist")
    assert not_found is None


def test_alert_repository_get_by_deduplication_key(db_session):
    """get_by_deduplication_key returns the correct alert or None."""
    repo = AlertRepository(db_session)

    db_session.add(_make_alert("dedup-q", "suspected_malware", "low", "new", "unique-dedup-key"))
    db_session.commit()

    found = repo.get_by_deduplication_key("unique-dedup-key")
    assert found is not None
    assert found.public_alert_id == "dedup-q"

    not_found = repo.get_by_deduplication_key("no-such-key")
    assert not_found is None


def test_alert_repository_pagination_and_count(db_session):
    """get_alerts respects page/page_size, filtering, and count_alerts is consistent."""
    repo = AlertRepository(db_session)

    for i in range(6):
        sev = "high" if i < 4 else "low"
        atype = "suspected_ddos" if i % 2 == 0 else "suspected_port_scan"
        db_session.add(_make_alert(f"p-{i}", atype, sev, "new", f"dk-p{i}"))
    db_session.commit()

    # Total
    total = repo.count_alerts()
    assert total == 6

    # Pagination
    page1 = repo.get_alerts(page=1, page_size=3)
    page2 = repo.get_alerts(page=2, page_size=3)
    assert len(page1) == 3
    assert len(page2) == 3
    # No overlap
    ids1 = {a.public_alert_id for a in page1}
    ids2 = {a.public_alert_id for a in page2}
    assert not ids1.intersection(ids2)

    # Severity filter
    high_alerts = repo.get_alerts(page=1, page_size=10, severity="high")
    assert len(high_alerts) == 4

    # Type filter
    ddos_alerts = repo.get_alerts(page=1, page_size=10, alert_type="suspected_ddos")
    assert len(ddos_alerts) == 3

    # count_alerts reflects filters
    assert repo.count_alerts(severity="high") == 4
    assert repo.count_alerts(severity="low") == 2
