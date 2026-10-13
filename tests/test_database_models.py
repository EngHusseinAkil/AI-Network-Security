import pytest
from sqlalchemy.orm import class_mapper
from database.base import Base
from database.models import (
    User, Device, TrafficRecord, ThreatLog, Alert,
    BlockedIP, BlockedDevice, SystemEvent, AuditLog
)

def test_models_importable():
    """Test that all models can be imported successfully."""
    assert User is not None
    assert Device is not None
    assert TrafficRecord is not None
    assert ThreatLog is not None
    assert Alert is not None
    assert BlockedIP is not None
    assert BlockedDevice is not None
    assert SystemEvent is not None
    assert AuditLog is not None

def test_expected_table_names_in_metadata():
    """Test that all expected table names exist in the Base metadata."""
    expected_tables = {
        "users", "devices", "traffic_records", "threat_logs",
        "alerts", "blocked_ips", "blocked_devices", "system_events", "audit_logs"
    }
    metadata_tables = set(Base.metadata.tables.keys())
    # Note: dummy_test_model from mixin tests might be in metadata_tables
    for table in expected_tables:
        assert table in metadata_tables, f"Table {table} missing from metadata"

def test_key_columns_exist():
    """Test that important key columns exist on the models."""
    assert "username" in User.__table__.columns
    assert "mac_address" in Device.__table__.columns
    assert "source_ip" in TrafficRecord.__table__.columns
    assert "severity" in ThreatLog.__table__.columns
    assert "status" in Alert.__table__.columns
    assert "ip_address" in BlockedIP.__table__.columns
    assert "mac_address" in BlockedDevice.__table__.columns
    assert "event_type" in SystemEvent.__table__.columns
    assert "action" in AuditLog.__table__.columns

def test_relationships_registered():
    """Test that relationships are correctly configured."""
    mapper = class_mapper(Device)
    assert "threat_logs" in mapper.relationships
    assert "blocked_devices" in mapper.relationships
    
    threat_mapper = class_mapper(ThreatLog)
    assert "device" in threat_mapper.relationships
    assert "traffic_record" in threat_mapper.relationships
    assert "alerts" in threat_mapper.relationships

def test_traffic_records_has_no_payload_blob():
    """Ensure traffic_records table does NOT have raw payload/blob column."""
    columns = TrafficRecord.__table__.columns.keys()
    
    # Check that generic blob/payload names don't exist
    assert "payload" not in columns
    assert "raw_payload" not in columns
    assert "raw_packet" not in columns
    assert "blob" not in columns
    
    # Ensure extracted_features is there as required
    assert "extracted_features" in columns
