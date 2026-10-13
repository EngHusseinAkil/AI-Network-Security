"""
Tests for Network Health module.
Verifies safe, non-destructive readiness checks.
"""

import pytest
from unittest.mock import patch

from network.health import (
    check_network_module_imports,
    check_scapy_availability,
    check_capture_backend_readiness,
    check_parser_readiness,
    check_flow_engine_readiness,
    check_feature_extractor_readiness,
    run_core_pipeline_self_test,
    get_network_status_report
)

def test_check_network_module_imports():
    assert check_network_module_imports() is True

def test_check_parser_readiness():
    assert check_parser_readiness() is True

def test_check_flow_engine_readiness():
    assert check_flow_engine_readiness() is True

def test_check_feature_extractor_readiness():
    assert check_feature_extractor_readiness() is True

def test_run_core_pipeline_self_test():
    status = run_core_pipeline_self_test()
    assert status["success"] is True
    assert status["error"] is None

@patch("network.health.check_scapy_availability")
def test_get_network_status_report_success(mock_scapy):
    """Verify success status when everything is operational."""
    mock_scapy.return_value = True
    report = get_network_status_report()
    
    assert report["modules_importable"] is True
    assert report["parser_ready"] is True
    assert report["flow_engine_ready"] is True
    assert report["feature_extractor_ready"] is True
    assert report["pipeline_self_test"]["success"] is True
    assert report["status"] == "success"

@patch("network.health.check_scapy_availability")
@patch("network.health.check_capture_backend_readiness")
def test_get_network_status_report_warning(mock_capture, mock_scapy):
    """Verify warning status when capture backend is unavailable but core is ready."""
    mock_scapy.return_value = False
    mock_capture.return_value = False
    
    report = get_network_status_report()
    
    assert report["status"] == "warning"
    assert "warning_message" in report

@patch("network.health.check_parser_readiness")
def test_get_network_status_report_failed(mock_parser):
    """Verify failed status when core components fail."""
    mock_parser.return_value = False
    
    report = get_network_status_report()
    
    assert report["status"] == "failed"
    assert "warning_message" not in report
