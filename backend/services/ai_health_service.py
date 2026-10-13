"""
AI Health Service for the Backend API.
Safely extracts AI platform readiness and subsystem status without exposing internals.
"""
from typing import Dict, Any
import logging

from ai.health import get_ai_status_report

logger = logging.getLogger(__name__)

class AIHealthService:
    """Service to retrieve safe AI readiness and integration status."""

    def __init__(self, registry_path: str = "models/registry.json", models_dir: str = "models"):
        self.registry_path = registry_path
        self.models_dir = models_dir

    def get_health_summary(self) -> Dict[str, Any]:
        """
        Executes internal AI health checks and maps them to a safe API structure.
        """
        try:
            report = get_ai_status_report(self.registry_path, self.models_dir)
        except Exception as e:
            logger.exception("Unexpected error while executing AI health checks: %s", e)
            return {
                "overall_status": "fail",
                "readiness_level": "not_ready",
                "total_checks": 0,
                "passed_checks": 0,
                "warning_checks": 0,
                "failed_checks": 1,
                "not_configured_checks": 0,
                "skipped_checks": 0,
                "checks": [{"name": "AI System", "status": "fail", "severity": "critical", "message": "AI health check execution failed."}]
            }

        overall_status = report.get("overall_status", "unknown")

        safe_checks = []
        not_configured_count = 0
        for check in report.get("checks", []):
            st = str(check.get("status", "unknown"))
            if st == "not_configured":
                not_configured_count += 1

            safe_checks.append({
                "name": str(check.get("name", "unknown")),
                "status": st,
                "severity": str(check.get("severity", "info")),
                "message": str(check.get("message", "Unknown status message."))
            })

        return {
            "overall_status": overall_status,
            "readiness_level": str(report.get("readiness_level", "unknown")),
            "total_checks": report.get("total_checks", 0),
            "passed_checks": report.get("passed", 0),
            "warning_checks": report.get("warnings", 0),
            "failed_checks": report.get("failed", 0),
            "not_configured_checks": not_configured_count,
            "skipped_checks": report.get("skipped", 0),
            "checks": safe_checks
        }
