import datetime
from dataclasses import dataclass
from typing import Callable
from sqlalchemy import select
from sqlalchemy.orm import Session

from alerts.constants import AlertType
from database.models import (
    User, Device, TrafficRecord, ThreatLog, Alert, BlockedIP, BlockedDevice, SystemEvent
)
from database.repositories import (
    UserRepository, DeviceRepository, TrafficRepository, ThreatRepository,
    AlertRepository, BlocklistRepository, SystemEventRepository
)
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

DEMO_TIMESTAMP = datetime.datetime(2025, 1, 15, 12, 0, tzinfo=datetime.timezone.utc)
DEMO_ALERT_ID = "00000000-0000-4000-8000-000000000001"
DEMO_ALERT_DEDUPLICATION_KEY = "demo-port-scan-0001"
DEMO_ALERT_TYPE = AlertType.SUSPECTED_PORT_SCAN.value
LEGACY_DEMO_ALERT_TYPE = "intrusion"


@dataclass(frozen=True)
class SeedEntityResult:
    created: int
    updated: int
    reused: int
    identifiers: tuple[str, ...]


@dataclass(frozen=True)
class DemoSeedResult:
    entities: dict[str, SeedEntityResult]


def _find_one(session: Session, model, *criteria):
    return session.execute(select(model).where(*criteria)).scalars().first()


def _result(items, existed: list[bool], identifier: Callable) -> SeedEntityResult:
    return SeedEntityResult(
        created=sum(not value for value in existed),
        updated=0,
        reused=sum(existed),
        identifiers=tuple(identifier(item) for item in items),
    )


def seed_admin_user(session: Session) -> User:
    raise DatabaseError(
        "Automatic administrator seeding is disabled. Use the users create CLI."
    )

def seed_sample_devices(session: Session) -> list[Device]:
    repo = DeviceRepository(session)
    devices = []

    mac_ips = [
        ("00:1A:2B:3C:4D:5E", "192.168.1.10", "Workstation"),
        ("AA:BB:CC:DD:EE:FF", "10.0.0.50", "Server"),
    ]

    now = DEMO_TIMESTAMP
    for mac, ip, dev_type in mac_ips:
        device = repo.get_by_mac_address(mac)
        if not device:
            device = Device(
                hostname=f"host-{ip.replace('.', '-')}",
                mac_address=mac,
                ip_address=ip,
                device_type=dev_type,
                risk_score=10.0,
                last_seen=now,
                created_at=now,
                updated_at=now,
            )
            repo.add(device)
        devices.append(device)

    logger.info("Sample devices seeded.")
    return devices

def seed_sample_traffic_records(session: Session) -> list[TrafficRecord]:
    repo = TrafficRepository(session)
    records = []
    for i in range(5):
        captured_at = DEMO_TIMESTAMP - datetime.timedelta(minutes=i)
        tr = _find_one(
            session,
            TrafficRecord,
            TrafficRecord.source_ip == "192.168.1.100",
            TrafficRecord.destination_ip == "10.0.0.200",
            TrafficRecord.source_port == 10000 + i,
            TrafficRecord.destination_port == 80,
            TrafficRecord.protocol == "TCP",
            TrafficRecord.captured_at == captured_at,
        )
        if not tr:
            tr = TrafficRecord(
                source_ip="192.168.1.100",
                destination_ip="10.0.0.200",
                source_port=10000 + i,
                destination_port=80,
                protocol="TCP",
                packet_size=1500,
                flow_duration=1.5,
                packet_count=10,
                byte_count=15000,
                extracted_features={"syn_flag": True, "ack_flag": True},
                captured_at=captured_at
            )
            repo.add(tr)
        records.append(tr)

    logger.info("Sample traffic records seeded.")
    return records

def seed_sample_threat_logs(session: Session, devices: list[Device], traffic: list[TrafficRecord]) -> list[ThreatLog]:
    repo = ThreatRepository(session)
    now = DEMO_TIMESTAMP
    dev_id = devices[0].id if devices else None
    tr_id = traffic[0].id if traffic else None

    t1 = _find_one(
        session,
        ThreatLog,
        ThreatLog.threat_type == "port_scan",
        ThreatLog.source_ip == "192.168.1.100",
        ThreatLog.destination_ip == "10.0.0.50",
        ThreatLog.detected_at == now,
    )
    if not t1:
        t1 = repo.add(ThreatLog(
            threat_type="port_scan",
            severity="medium",
            confidence_score=0.85,
            source_ip="192.168.1.100",
            destination_ip="10.0.0.50",
            device_id=dev_id,
            traffic_record_id=tr_id,
            description="Sequential port scan detected",
            detected_at=now,
            created_at=now,
            updated_at=now,
        ))
    t2_at = now - datetime.timedelta(hours=1)
    t2 = _find_one(
        session,
        ThreatLog,
        ThreatLog.threat_type == "malware_signature",
        ThreatLog.source_ip == "10.0.0.50",
        ThreatLog.destination_ip == "192.168.1.10",
        ThreatLog.detected_at == t2_at,
    )
    if not t2:
        t2 = repo.add(ThreatLog(
            threat_type="malware_signature",
            severity="critical",
            confidence_score=0.99,
            source_ip="10.0.0.50",
            destination_ip="192.168.1.10",
            description="Known ransomware pattern",
            detected_at=t2_at,
            created_at=t2_at,
            updated_at=t2_at,
        ))
    logger.info("Sample threat logs seeded.")
    return [t1, t2]

def seed_sample_alerts(session: Session, threats: list[ThreatLog]) -> list[Alert]:
    repo = AlertRepository(session)
    t1_id = threats[0].id if threats else None

    a1 = repo.get_by_public_id(DEMO_ALERT_ID)
    if not a1:
        a1 = Alert(
            threat_log_id=t1_id,
            public_alert_id=DEMO_ALERT_ID,
            alert_type=DEMO_ALERT_TYPE,
            severity="medium",
            title="Intrusion Detected",
            description="Port scan requires investigation",
            source_category="network",
            predicted_canonical_label="port_scan",
            confidence_score=0.85,
            risk_score=0.65,
            schema_version="1.0",
            policy_version="demo-1.0",
            reason_code="DEMO_PORT_SCAN",
            deduplication_key=DEMO_ALERT_DEDUPLICATION_KEY,
            status="new",
            created_at=DEMO_TIMESTAMP,
            updated_at=DEMO_TIMESTAMP,
            safe_metadata={"demo": True},
        )
        repo.add(a1)
    elif a1.alert_type == LEGACY_DEMO_ALERT_TYPE:
        a1.alert_type = DEMO_ALERT_TYPE
        session.flush()
        logger.info("Repaired legacy deterministic demo alert type.")
    logger.info("Sample alerts seeded.")
    return [a1]

def seed_sample_blocklists(session: Session, devices: list[Device]) -> None:
    repo = BlocklistRepository(session)
    now = DEMO_TIMESTAMP

    if not repo.find_active_ip_block("10.0.0.99"):
        repo.add_ip_block(BlockedIP(
            ip_address="10.0.0.99",
            reason="Malicious activity",
            severity="high",
            blocked_at=now,
            expires_at=datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
            is_active=True,
            created_at=now,
            updated_at=now,
        ))

    mac = "00:1A:2B:3C:4D:5E"
    dev_id = devices[0].id if devices else None
    if not repo.find_active_device_block(mac):
        repo.add_device_block(BlockedDevice(
            device_id=dev_id,
            mac_address=mac,
            reason="Compromised host",
            severity="critical",
            blocked_at=now,
            expires_at=datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc),
            is_active=True,
            created_at=now,
            updated_at=now,
        ))
    logger.info("Sample blocklists seeded.")

def seed_system_events(session: Session) -> None:
    repo = SystemEventRepository(session)
    event = _find_one(
        session,
        SystemEvent,
        SystemEvent.event_type == "system_startup",
        SystemEvent.message == "System initialized with seed data",
        SystemEvent.source == "seed",
    )
    if not event:
        repo.add(SystemEvent(
            event_type="system_startup",
            level="info",
            message="System initialized with seed data",
            source="seed",
            created_at=DEMO_TIMESTAMP,
            updated_at=DEMO_TIMESTAMP,
        ))
    logger.info("Sample system events seeded.")

def seed_demo_data(session: Session, confirm: bool = False) -> DemoSeedResult:
    """
    Seeds all demo data.
    Must be explicitly confirmed and is never permitted in production.
    """
    from config.config import settings
    from config.settings import ProductionSettings

    if not confirm:
        logger.warning("Attempted to seed demo data without confirmation.")
        raise DatabaseError("Safety abort: confirm=True is required to seed demo data.")

    is_production = isinstance(settings, ProductionSettings)
    if is_production:
        logger.error("Attempted to seed demo data in production.")
        raise DatabaseError("Safety abort: Cannot seed demo data in a production environment.")

    logger.info("Starting to seed demo data...")
    device_existing = [
        DeviceRepository(session).get_by_mac_address(mac) is not None
        for mac in ("00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF")
    ]
    devices = seed_sample_devices(session)

    traffic_existing = []
    for i in range(5):
        traffic_existing.append(_find_one(
            session,
            TrafficRecord,
            TrafficRecord.source_ip == "192.168.1.100",
            TrafficRecord.source_port == 10000 + i,
            TrafficRecord.captured_at == DEMO_TIMESTAMP - datetime.timedelta(minutes=i),
        ) is not None)
    traffic = seed_sample_traffic_records(session)

    threat_specs = (
        ("port_scan", DEMO_TIMESTAMP),
        ("malware_signature", DEMO_TIMESTAMP - datetime.timedelta(hours=1)),
    )
    threat_existing = [
        _find_one(
            session, ThreatLog,
            ThreatLog.threat_type == threat_type,
            ThreatLog.detected_at == detected_at,
        ) is not None
        for threat_type, detected_at in threat_specs
    ]
    threats = seed_sample_threat_logs(session, devices, traffic)

    existing_alert = AlertRepository(session).get_by_public_id(DEMO_ALERT_ID)
    alert_existing = existing_alert is not None
    alert_repair_needed = bool(
        existing_alert and existing_alert.alert_type == LEGACY_DEMO_ALERT_TYPE
    )
    alerts = seed_sample_alerts(session, threats)

    blocklist_repo = BlocklistRepository(session)
    block_existing = [
        blocklist_repo.find_active_ip_block("10.0.0.99") is not None,
        blocklist_repo.find_active_device_block("00:1A:2B:3C:4D:5E") is not None,
    ]
    seed_sample_blocklists(session, devices)

    event_existing = [_find_one(
        session,
        SystemEvent,
        SystemEvent.event_type == "system_startup",
        SystemEvent.message == "System initialized with seed data",
        SystemEvent.source == "seed",
    ) is not None]
    seed_system_events(session)

    logger.info("Demo data seeding completed successfully.")
    return DemoSeedResult(entities={
        "devices": _result(devices, device_existing, lambda item: item.mac_address),
        "traffic_records": _result(
            traffic, traffic_existing,
            lambda item: f"{item.source_ip}:{item.source_port}->{item.destination_ip}:{item.destination_port}",
        ),
        "threats": _result(
            threats, threat_existing,
            lambda item: f"{item.threat_type}:{item.detected_at.isoformat()}",
        ),
        "alerts": SeedEntityResult(
            created=int(not alert_existing),
            updated=int(alert_repair_needed),
            reused=int(alert_existing and not alert_repair_needed),
            identifiers=tuple(item.public_alert_id for item in alerts),
        ),
        "blocklist_records": SeedEntityResult(
            created=sum(not value for value in block_existing),
            updated=0,
            reused=sum(block_existing),
            identifiers=("10.0.0.99", "00:1A:2B:3C:4D:5E"),
        ),
        "system_events": SeedEntityResult(
            created=sum(not value for value in event_existing),
            updated=0,
            reused=sum(event_existing),
            identifiers=("system_startup:seed",),
        ),
    })
