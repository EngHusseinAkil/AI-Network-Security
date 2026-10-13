from unittest.mock import patch
from utils.health_check import run_health_check, check_python_version, check_required_packages

@patch("ai.health.get_ai_status_report")
def test_run_health_check(mock_get_ai):
    mock_get_ai.return_value = {
        "overall_status": "pass",
        "readiness_level": "integration_ready",
        "passed": 3,
        "failed": 0,
        "warnings": 0,
        "checks": []
    }
    report = run_health_check()
    assert report["overall_status"] in ["success", "warning"]
    assert report["total_checks"] == 9

def test_check_required_packages():
    res = check_required_packages()
    assert res["status"] == "success"
