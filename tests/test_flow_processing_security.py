from dataclasses import fields
from pathlib import Path
import subprocess
import sys
import threading

from backend.app_factory import create_app
from network.flow_models import MetadataFlowRecord

FLOW_MODULES = [
    "network.flow_config", "network.flow_models",
    "network.flow_aggregation_service", "network.flow_feature_service",
    "network.capture_flow_processor",
]


def test_flow_modules_do_not_import_scapy():
    code = (
        f"import {', '.join(FLOW_MODULES)}; import sys; "
        "assert not any(x == 'scapy' or x.startswith('scapy.') for x in sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_flow_record_has_no_raw_or_native_fields():
    names = {field.name for field in fields(MetadataFlowRecord)}
    assert names.isdisjoint({"packet", "payload", "raw_bytes", "native_interface"})


def test_app_startup_creates_no_processing_thread():
    before = {thread.ident for thread in threading.enumerate()}
    create_app({"TESTING": True, "SECRET_KEY": "flow-security"})
    after = {thread.ident for thread in threading.enumerate()}
    assert after == before


def test_flow_modules_have_no_forbidden_side_effect_integrations():
    root = Path(__file__).parents[1]
    text = "\n".join((root / module.replace(".", "/")).with_suffix(".py").read_text()
                     for module in FLOW_MODULES)
    forbidden = [
        "ThreatLog", "alert_policy", "inference_service", "notification",
        "requests.", "httpx.", "pip install", ".pcap", "repository",
    ]
    assert all(value not in text for value in forbidden)


def test_no_public_json_flow_write_api():
    app = create_app({"TESTING": True, "SECRET_KEY": "flow-security"})
    flow_rules = [rule.rule for rule in app.url_map.iter_rules() if "/flows/" in rule.rule]
    assert flow_rules == [
        "/dashboard/monitoring/flows/process",
        "/dashboard/monitoring/flows/evaluate",
        "/dashboard/monitoring/flows/evaluations/<evaluation_id>/alerts",
    ]
    alert_rule = next(
        rule for rule in app.url_map.iter_rules()
        if rule.rule.endswith("/evaluations/<evaluation_id>/alerts")
    )
    assert alert_rule.methods == {"OPTIONS", "POST"}
