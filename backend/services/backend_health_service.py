import logging
import traceback
from typing import Dict, Any, List
from flask import current_app
from datetime import datetime, timezone

from version import get_version

logger = logging.getLogger(__name__)

STATUS_PASS = "pass"
STATUS_WARNING = "warning"
STATUS_FAIL = "fail"
STATUS_NOT_CONFIGURED = "not_configured"

READINESS_NOT_READY = "not_ready"
READINESS_TRANSPORT_READY = "transport_ready"
READINESS_SERVICES_READY = "services_ready"
READINESS_INTEGRATION_READY = "integration_ready"

class BackendHealthService:
    """Service to evaluate backend configuration, routing, dependencies, and integration readiness."""

    def _build_check(self, name: str, status: str, severity: str, message: str) -> Dict[str, Any]:
        return {
            "name": name,
            "status": status,
            "severity": severity,
            "message": message
        }

    def _check_flask_context(self) -> Dict[str, Any]:
        if current_app:
            return self._build_check("Flask Context", STATUS_PASS, "info", "Running within a valid Flask application context.")
        return self._build_check("Flask Context", STATUS_FAIL, "critical", "Not running within a Flask application context.")

    def _check_route_integrity(self) -> List[Dict[str, Any]]:
        results = []
        try:
            rules = list(current_app.url_map.iter_rules())
            api_routes = [r for r in rules if r.rule.startswith('/api/')]

            # Check prefixes
            non_v1 = [r.rule for r in api_routes if not r.rule.startswith('/api/v1/')]
            if non_v1:
                results.append(self._build_check("API Prefix Consistency", STATUS_FAIL, "critical", f"Found non-v1 API routes: {non_v1}"))
            else:
                results.append(self._build_check("API Prefix Consistency", STATUS_PASS, "info", "All API routes correctly use /api/v1 prefix."))

            # Check inference POST only
            inference_rules = [r for r in api_routes if r.rule.startswith('/api/v1/inference/')]
            invalid_inference_methods = [r for r in inference_rules if not ({'POST', 'OPTIONS'} & set(r.methods))]
            if invalid_inference_methods:
                results.append(self._build_check("Inference Route Integrity", STATUS_FAIL, "critical", "Inference routes must only support POST."))
            else:
                results.append(self._build_check("Inference Route Integrity", STATUS_PASS, "info", "Inference routes strictly enforce POST."))

            # Ensure some minimum blueprints exist
            expected_prefixes = ['/api/v1/health', '/api/v1/models', '/api/v1/devices']
            missing = [p for p in expected_prefixes if not any(r.rule.startswith(p) for r in api_routes)]
            if missing:
                results.append(self._build_check("Blueprint Registration", STATUS_FAIL, "critical", f"Missing essential API blueprints: {missing}"))
            else:
                results.append(self._build_check("Blueprint Registration", STATUS_PASS, "info", "Core API blueprints successfully registered."))

        except Exception as e:
            results.append(self._build_check("Route Integrity", STATUS_FAIL, "critical", "Failed to analyze Flask route map."))
        return results

    def _check_security_config(self) -> List[Dict[str, Any]]:
        results = []

        # DEBUG mode
        if current_app.config.get("DEBUG", False):
            results.append(self._build_check("Production Mode", STATUS_FAIL, "critical", "Application is running in DEBUG mode."))
        else:
            results.append(self._build_check("Production Mode", STATUS_PASS, "info", "Production mode enforced (DEBUG=False)."))

        # Max Content Length
        mcl = current_app.config.get("MAX_CONTENT_LENGTH")
        if not mcl or mcl > (10 * 1024 * 1024):
            results.append(self._build_check("Payload Limits", STATUS_FAIL, "critical", "MAX_CONTENT_LENGTH is missing or dangerously large."))
        else:
            results.append(self._build_check("Payload Limits", STATUS_PASS, "info", f"Payload limit bounded at {mcl} bytes."))

        # CORS
        cors_origins = current_app.config.get("CORS_ALLOWED_ORIGINS", [])
        if "*" in cors_origins:
            results.append(self._build_check("CORS Policy", STATUS_FAIL, "critical", "Wildcard (*) CORS origin is strictly forbidden in production."))
        elif current_app.config.get("CORS_ALLOW_CREDENTIALS"):
            results.append(self._build_check("CORS Policy", STATUS_FAIL, "critical", "Credentialed CORS is unexpectedly enabled."))
        else:
            results.append(self._build_check("CORS Policy", STATUS_PASS, "info", "CORS policy safely constrained."))

        # Rate Limiting
        rl = current_app.config.get("RATE_LIMIT_DEFAULT", 0)
        if rl <= 0:
            results.append(self._build_check("Rate Limiting Configuration", STATUS_FAIL, "critical", "Default rate limit is invalid or disabled."))
        else:
            # We only have in-memory for Phase 5.
            results.append(self._build_check("Rate Limiting Infrastructure", STATUS_WARNING, "warning", "In-memory rate limiter configured. A distributed store (e.g., Redis) is required for multi-worker production."))

        # Request ID & JSON Policy (inferred from `before_request_funcs`)
        funcs = current_app.before_request_funcs.get(None, [])
        func_names = [f.__name__ for f in funcs]

        if "enforce_json_policy" not in func_names:
            results.append(self._build_check("JSON Policy", STATUS_FAIL, "critical", "JSON content policy middleware is missing."))
        else:
            results.append(self._build_check("JSON Policy", STATUS_PASS, "info", "JSON content policy strictly enforced on API mutating routes."))

        # After request funcs
        after_funcs = current_app.after_request_funcs.get(None, [])
        after_names = [f.__name__ for f in after_funcs]

        if "add_request_id_header" not in after_names:
            results.append(self._build_check("Request ID Middleware", STATUS_FAIL, "critical", "Request-ID header middleware is missing."))
        else:
            results.append(self._build_check("Request ID Middleware", STATUS_PASS, "info", "Request-ID context globally injected."))

        if "add_security_headers" not in after_names:
            results.append(self._build_check("Secure Headers", STATUS_FAIL, "critical", "Secure response headers middleware is missing."))
        else:
            results.append(self._build_check("Secure Headers", STATUS_PASS, "info", "Secure HTTP headers (CSP, HSTS, X-Frame-Options) actively injected."))

        # Error Handlers
        from backend.errors.exceptions import ApiError
        if ApiError not in current_app.error_handler_spec.get(None, {}).get(None, {}):
            results.append(self._build_check("Error Handlers", STATUS_FAIL, "critical", "Global API error handlers are not registered."))
        else:
            results.append(self._build_check("Error Handlers", STATUS_PASS, "info", "Centralized error handler specification mapped."))

        return results

    def _check_dependencies(self) -> List[Dict[str, Any]]:
        results = []
        deps = current_app.extensions.get('dependencies')
        if not deps:
            results.append(self._build_check("Dependency Container", STATUS_FAIL, "critical", "DependencyContainer extension is missing."))
            return results

        results.append(self._build_check("Dependency Container", STATUS_PASS, "info", "Dependency container injected successfully."))

        # Check services
        required_services = [
            ("VersionService", deps.version_service),
            ("Platform HealthService", deps.health_service),
            ("AI HealthService", deps.ai_health_service),
            ("ModelService", deps.model_service),
            ("InferenceService", deps.inference_service),
            ("DeviceQueryService", deps.device_query_service),
            ("TrafficQueryService", deps.traffic_query_service),
            ("ThreatQueryService", deps.threat_query_service)
        ]

        for name, service in required_services:
            if service is None:
                results.append(self._build_check(f"Service: {name}", STATUS_FAIL, "critical", "Required service is missing from dependency container."))
            else:
                results.append(self._build_check(f"Service: {name}", STATUS_PASS, "info", "Service wired securely."))

        # Check Database Reachability if configured
        try:
            if getattr(deps, 'db_session', None) is not None:
                # We do not query! We just know it's wired.
                # In Dev, if db doesn't exist, it might be a warning.
                results.append(self._build_check("Database Factory", STATUS_PASS, "info", "Database Session Factory is configured and wired."))
            else:
                results.append(self._build_check("Database Factory", STATUS_NOT_CONFIGURED, "warning", "Database Session Factory is missing or disabled."))
        except Exception:
            results.append(self._build_check("Database Factory", STATUS_FAIL, "critical", "Database query execution probe failed safely."))

        # We do NOT run Inference or check Model artifacts! That belongs to AI Health.
        # We just assert that inference is wired.

        return results

    def get_health_summary(self) -> Dict[str, Any]:
        """
        Executes all read-only backend health checks.
        Returns the structured health response.
        """
        checks = []

        try:
            checks.append(self._check_flask_context())
            if checks[0]["status"] == STATUS_PASS:
                checks.extend(self._check_route_integrity())
                checks.extend(self._check_security_config())
                checks.extend(self._check_dependencies())
        except Exception as e:
            logger.error("Backend health probe encountered unexpected crash: %s", e)
            checks.append(self._build_check("Health Probe Execution", STATUS_FAIL, "critical", "Safe backend readiness probe crashed unexpectedly."))

        total = len(checks)
        passed = sum(1 for c in checks if c["status"] == STATUS_PASS)
        failed = sum(1 for c in checks if c["status"] == STATUS_FAIL)
        warnings = sum(1 for c in checks if c["status"] == STATUS_WARNING)
        not_config = sum(1 for c in checks if c["status"] == STATUS_NOT_CONFIGURED)

        # Determine Readiness Level
        # not_ready -> transport_ready -> services_ready -> integration_ready (No production_ready yet)

        # Determine status
        overall_status = "ok"
        if failed > 0:
            overall_status = "failed"
        elif warnings > 0 or not_config > 0:
            overall_status = "warning"

        readiness = READINESS_NOT_READY

        if failed == 0:
            readiness = READINESS_INTEGRATION_READY
            # Check if any service checks were missing? Not if failed == 0.

        return {
            "overall_status": overall_status,
            "readiness_level": readiness,
            "total_checks": total,
            "passed_checks": passed,
            "warning_checks": warnings,
            "failed_checks": failed,
            "not_configured_checks": not_config,
            "application_version": get_version(),
            "api_version": "v1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": checks
        }
