"""
Application entry point for the AI Network Security Platform.
Orchestrates initialization of all foundation components.
"""
import sys
from utils.exceptions import ApplicationError

def display_startup_banner(settings, print_version_info) -> None:
    """Displays the project startup banner with version and environment info."""
    print("")
    print("=" * 50)
    print("  AI-POWERED NETWORK SECURITY PLATFORM")
    print("=" * 50)
    print_version_info()
    print(f"  Environment: {settings.LOG_LEVEL} logging")
    print(f"  Debug Mode:  {settings.DEBUG}")
    print("=" * 50)
    print("")

def initialize_application() -> int:
    """
    Runs the full application initialization sequence.
    Returns 0 on success, 1 on failure.
    """
    try:
        # Step 1: Load configuration
        from config import settings

        # Step 2: Initialize the centralized logger
        from utils.logger import get_logger
        logger = get_logger("App")

        # Step 3: Log project startup
        from version import get_version, print_version_info
        logger.info("Starting AI Network Security Platform v%s ...", get_version())

        # Step 4: Display project version information
        display_startup_banner(settings, print_version_info)

        # Step 5: Verify and create required directories
        logger.info("Verifying project directory structure...")
        from utils.directory_manager import ensure_required_directories
        ensure_required_directories()
        logger.info("Directory structure verified successfully.")

        # Step 6 & 7: Run the complete health check and display report
        logger.info("Running startup health check...")
        from utils.health_check import run_health_check, print_health_report
        report = run_health_check()
        print_health_report(report)

        if report["overall_status"] == "failed":
            logger.error("Health check failed. Status: %s", report["overall_status"])
            return 1
        elif report["overall_status"] == "warning":
            logger.warning("Health check completed with warnings.")

        # Step 8: Log successful initialization
        logger.info("Application initialized successfully. Ready for development.")
        print("  >> Initialization complete. System is ready.")
        print("")
        return 0

    except ApplicationError as e:
        print(f"\n  [ERROR] Application initialization failed: {e}\n")
        try:
            from utils.logger import get_logger
            get_logger("App").error("ApplicationError during initialization: %s", e)
        except Exception:
            pass
        return 1

    except Exception as e:
        print(f"\n  [FATAL] Unexpected error during initialization: {e}\n")
        try:
            from utils.logger import get_logger
            get_logger("App").exception("Unexpected error during initialization: %s", e)
        except Exception:
            pass
        return 1

def main() -> None:
    """Main entry point. Calls initialization and exits with the appropriate code."""
    # Check for optional web bridge
    if "--web" in sys.argv:
        exit_code = initialize_application()
        if exit_code != 0:
            sys.exit(exit_code)

        from backend.app_factory import create_app
        print("\n  >> Starting Flask Application Backend...\n")
        app = create_app()
        # In a real production deployment, a WSGI server like gunicorn would be used.
        # This is strictly for the development/testing bridge.
        app.run(host="127.0.0.1", port=5000, debug=app.config.get("DEBUG", False))
        sys.exit(0)
    else:
        exit_code = initialize_application()
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
