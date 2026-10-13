"""
Health Service for the Backend API.
Wraps project health checks into safe API contracts.
"""
from typing import Dict, Any
import logging

from utils.health_check import run_health_check
from version import get_version

logger = logging.getLogger(__name__)

class HealthService:
    """Service to retrieve and map overall platform health."""

    def get_health_summary(self) -> Dict[str, Any]:
        """
        Executes internal project health checks and maps them to a safe API structure.
        """
        try:
            # We call the existing centralized project health check
            report = run_health_check()
        except Exception as e:
            # Fallback if the health check system itself blows up unexpectedly
            logger.exception("Unexpected error while executing project health checks: %s", e)
            return {
                "overall_status": "failed",
                "total_checks": 0,
                "passed_checks": 0,
                "warning_checks": 0,
                "failed_checks": 1,
                "checks": [{"name": "System", "status": "failed", "message": "Health check execution failed."}],
                "application_version": get_version()
            }

        overall_status = report.get("overall_status", "unknown")

        safe_checks = []
        for check in report.get("checks", []):
            safe_checks.append({
                "name": str(check.get("name", "unknown")),
                "status": str(check.get("status", "unknown")),
                "message": str(check.get("message", "Unknown status message."))
            })

        return {
            "overall_status": overall_status,
            "total_checks": report.get("total_checks", 0),
            "passed_checks": report.get("passed", 0),
            "warning_checks": report.get("warnings", 0),
            "failed_checks": report.get("failed", 0),
            "checks": safe_checks,
            "application_version": get_version()
        }
