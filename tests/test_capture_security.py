from dataclasses import fields
from pathlib import Path

from backend.app_factory import create_app
from network.capture_models import CapturedPacketMetadata


def test_metadata_has_no_sensitive_or_raw_fields():
    names = {field.name for field in fields(CapturedPacketMetadata)}
    forbidden = {"payload", "packet", "bytes", "source_ip", "destination_ip",
                 "mac", "port", "credentials", "cookies", "content"}
    assert names.isdisjoint(forbidden)


def test_status_poll_does_not_touch_queue():
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    service = app.extensions["dependencies"].capture_service
    before = service.get_metadata_snapshot if False else service._metadata_queue.qsize()
    app.test_client().get("/api/v1/monitoring/status")
    assert service._metadata_queue.qsize() == before


def test_no_runtime_install_or_pcap_code():
    root = Path(__file__).parents[1]
    source = "\n".join(path.read_text(encoding="utf-8") for path in [
        root / "network" / "capture_service.py", root / "network" / "fake_source.py",
        root / "dashboard" / "capture_service.py",
    ])
    assert "pip install" not in source and ".pcap" not in source


def test_capture_core_has_no_milestone_16_imports():
    text = (Path(__file__).parents[1] / "network" / "capture_service.py").read_text()
    assert all(name not in text for name in [
        "ThreatLog", "inference", "policy", "notification", "blocking", "requests."
    ])


def test_no_public_json_capture_write_endpoint():
    app = create_app({"TESTING": True, "SECRET_KEY": "security"})
    rules = [rule.rule for rule in app.url_map.iter_rules() if "capture" in rule.rule]
    assert rules and all(rule.startswith("/dashboard/") for rule in rules)
