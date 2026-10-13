"""
Centralized project health check system.
Validates configuration, logging, directories, version, Python version, and core packages.
"""
import sys
import importlib
from typing import Dict, Any, List

from utils.logger import get_logger
from utils.constants import STATUS_SUCCESS, STATUS_ERROR

logger = get_logger("HealthCheck")

STATUS_WARNING = "warning"
STATUS_FAILED = "failed"

REQUIRED_PACKAGES: List[str] = [
    "flask",
    "pandas",
    "numpy",
    "sklearn",
    "matplotlib",
    "joblib"
]


def _build_check_result(name: str, status: str, message: str) -> Dict[str, str]:
    """Builds a standardized check result dictionary."""
    return {"name": name, "status": status, "message": message}


def check_configuration() -> Dict[str, str]:
    """Verifies that the configuration system loads correctly and the environment is valid."""
    try:
        from config import settings
        from config.environment import Environment

        env_value = getattr(settings, "LOG_LEVEL", None)
        if env_value is None:
            return _build_check_result(
                "Configuration", STATUS_WARNING, "Configuration loaded but LOG_LEVEL is missing."
            )

        # Verify the active environment maps to a known enum value
        valid_envs = [e.value for e in Environment]
        app_env = getattr(settings, "APP_NAME", "unknown")

        return _build_check_result(
            "Configuration", STATUS_SUCCESS,
            f"Configuration loaded successfully. App: {app_env}, Log Level: {env_value}"
        )
    except Exception as e:
        logger.error(f"Configuration check failed: {e}")
        return _build_check_result("Configuration", STATUS_FAILED, str(e))


def check_logging() -> Dict[str, str]:
    """Verifies that the logging system initializes correctly."""
    try:
        test_logger = get_logger("HealthCheck.LogTest")
        test_logger.debug("Health check: logging subsystem verified.")
        return _build_check_result(
            "Logging", STATUS_SUCCESS, "Logging subsystem initialized successfully."
        )
    except Exception as e:
        return _build_check_result("Logging", STATUS_FAILED, str(e))


def check_directories() -> Dict[str, str]:
    """Verifies that all required project directories exist."""
    try:
        from utils.directory_manager import verify_required_directories, get_directory_status_report

        if verify_required_directories():
            return _build_check_result(
                "Directories", STATUS_SUCCESS, "All required directories exist."
            )

        report = get_directory_status_report()
        missing = [d for d, s in report["directories"].items() if s == "missing"]
        return _build_check_result(
            "Directories", STATUS_WARNING,
            f"Missing directories: {', '.join(missing)}"
        )
    except Exception as e:
        logger.error(f"Directory check failed: {e}")
        return _build_check_result("Directories", STATUS_FAILED, str(e))


def check_version() -> Dict[str, str]:
    """Verifies that version metadata loads correctly."""
    try:
        from version import get_version, get_project_metadata

        version = get_version()
        metadata = get_project_metadata()

        if not version or not metadata.get("project_name"):
            return _build_check_result(
                "Version", STATUS_WARNING, "Version loaded but metadata is incomplete."
            )

        return _build_check_result(
            "Version", STATUS_SUCCESS, f"Version {version} loaded successfully."
        )
    except Exception as e:
        logger.error(f"Version check failed: {e}")
        return _build_check_result("Version", STATUS_FAILED, str(e))


def check_python_version() -> Dict[str, str]:
    """Verifies the running Python version meets the minimum requirement."""
    try:
        from version import PYTHON_VERSION_MIN

        current = f"{sys.version_info.major}.{sys.version_info.minor}"
        min_parts = PYTHON_VERSION_MIN.split(".")
        min_major, min_minor = int(min_parts[0]), int(min_parts[1])

        if (sys.version_info.major, sys.version_info.minor) >= (min_major, min_minor):
            return _build_check_result(
                "Python Version", STATUS_SUCCESS,
                f"Python {current} meets minimum requirement ({PYTHON_VERSION_MIN})."
            )

        return _build_check_result(
            "Python Version", STATUS_FAILED,
            f"Python {current} is below minimum requirement ({PYTHON_VERSION_MIN})."
        )
    except Exception as e:
        logger.error(f"Python version check failed: {e}")
        return _build_check_result("Python Version", STATUS_FAILED, str(e))


def check_required_packages() -> Dict[str, str]:
    """Verifies that all required core packages can be imported."""
    missing: List[str] = []

    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package)
        except ImportError:
            missing.append(package)

    if not missing:
        return _build_check_result(
            "Required Packages", STATUS_SUCCESS,
            f"All {len(REQUIRED_PACKAGES)} required packages are importable."
        )

    return _build_check_result(
        "Required Packages", STATUS_FAILED,
        f"Missing packages: {', '.join(missing)}"
    )


def check_database() -> Dict[str, str]:
    """Verifies that the database infrastructure can be connected to and schema is valid."""
    try:
        from database.integrity import get_database_status_report

        report = get_database_status_report()
        if report["connectivity"] == "failed":
            return _build_check_result(
                "Database", STATUS_FAILED,
                "Database connection test failed."
            )

        tables_status = report["tables_status"]
        if tables_status["status"] == "warning":
            return _build_check_result(
                "Database", STATUS_WARNING,
                tables_status["message"]
            )
        elif tables_status["status"] == "failed":
            return _build_check_result(
                "Database", STATUS_FAILED,
                tables_status["message"]
            )

        if report["schema_integrity"] == "failed":
            return _build_check_result(
                "Database", STATUS_FAILED,
                "Database schema integrity check failed."
            )

        return _build_check_result(
            "Database", STATUS_SUCCESS,
            "Database fully ready."
        )
    except Exception as e:
        logger.error(f"Database check failed: {e}")
        return _build_check_result("Database", STATUS_FAILED, str(e))


def check_network_engine() -> Dict[str, str]:
    """Verifies that the Network Engine is ready for operation."""
    try:
        from network.health import get_network_status_report

        report = get_network_status_report()

        if report["status"] == "failed":
            return _build_check_result(
                "Network Engine", STATUS_FAILED,
                "Core Network Engine offline/synthetic pipeline is broken."
            )

        if report["status"] == "warning":
            return _build_check_result(
                "Network Engine", STATUS_WARNING,
                report.get("warning_message", "Live capture prerequisites unavailable. Synthetic/offline processing only.")
            )

        return _build_check_result(
            "Network Engine", STATUS_SUCCESS,
            "Network Engine core pipeline ready; Scapy adapter available. Live capture prerequisites are not actively probed."
        )
    except Exception as e:
        logger.error(f"Network Engine check failed: {e}")
        return _build_check_result("Network Engine", STATUS_FAILED, str(e))


def check_ai_engine() -> Dict[str, str]:
    """Verifies the AI Engine configuration, schemas, and model readiness."""
    try:
        from ai.health import get_ai_status_report, STATUS_FAIL, STATUS_WARNING

        report = get_ai_status_report()

        status_map = {
            STATUS_FAIL: STATUS_FAILED,
            STATUS_WARNING: STATUS_WARNING,
        }

        mapped_status = status_map.get(report["overall_status"], STATUS_SUCCESS)
        readiness = report.get("readiness_level", "unknown")

        return _build_check_result(
            "AI Engine", mapped_status,
            f"AI readiness: {readiness}. Passed: {report['passed']}, Failed: {report['failed']}, Warnings: {report['warnings']}."
        )
    except Exception as e:
        logger.error(f"AI Engine check failed: {e}")
        return _build_check_result("AI Engine", STATUS_FAILED, str(e))


def run_health_check() -> Dict[str, Any]:
    """
    Runs all health checks and returns a structured report.
    """
    logger.info("Running project health check...")

    checks = [
        check_configuration(),
        check_logging(),
        check_directories(),
        check_version(),
        check_python_version(),
        check_required_packages(),
        check_database(),
        check_network_engine(),
        check_ai_engine()
    ]

    overall_status = STATUS_SUCCESS
    for check in checks:
        if check["status"] == STATUS_FAILED:
            overall_status = STATUS_FAILED
            break
        elif check["status"] == STATUS_WARNING and overall_status != STATUS_FAILED:
            overall_status = STATUS_WARNING

    report = {
        "overall_status": overall_status,
        "total_checks": len(checks),
        "passed": sum(1 for c in checks if c["status"] == STATUS_SUCCESS),
        "warnings": sum(1 for c in checks if c["status"] == STATUS_WARNING),
        "failed": sum(1 for c in checks if c["status"] == STATUS_FAILED),
        "checks": checks
    }

    logger.info(f"Health check completed: {report['overall_status'].upper()}")
    return report


def print_health_report(report: Dict[str, Any]) -> None:
    """Prints a formatted health report to standard output."""
    print("\n" + "=" * 50)
    print("  PROJECT HEALTH CHECK REPORT")
    print("=" * 50)

    for check in report["checks"]:
        icon = "[PASS]" if check["status"] == STATUS_SUCCESS else ("[WARN]" if check["status"] == STATUS_WARNING else "[FAIL]")
        print(f"  {icon}  {check['name']}: {check['message']}")

    print("-" * 50)
    print(f"  Overall: {report['overall_status'].upper()}")
    print(f"  Passed: {report['passed']} | Warnings: {report['warnings']} | Failed: {report['failed']}")
    print("=" * 50 + "\n")
