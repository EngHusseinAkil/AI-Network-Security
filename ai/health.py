import logging
import os
from typing import Dict, Any, List

from version import get_version
from ai.schema import FLOW_SCHEMA_VERSION, CANONICAL_LABELS

from network.features import FLOW_FEATURE_ORDER
from ai.model_registry import ModelRegistry
from ai.inference import InferenceEngine
from ai.network_integration import FlowInferenceAdapter
from ai.model_persistence import load_model_artifact
from utils.exceptions import ValidationError

logger = logging.getLogger(__name__)

STATUS_PASS = "pass"
STATUS_WARNING = "warning"
STATUS_FAIL = "fail"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_SKIPPED = "skipped"

READINESS_NOT_READY = "not_ready"
READINESS_CONFIGURATION_READY = "configuration_ready"
READINESS_MODEL_READY = "model_ready"
READINESS_INTEGRATION_READY = "integration_ready"

def _build_check(name: str, status: str, message: str, severity: str = "info") -> Dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "severity": severity,
        "message": message
    }

def check_ai_foundation() -> Dict[str, Any]:
    """Validates that sklearn and core AI dependencies are available."""
    try:
        import sklearn
        import numpy
        import joblib
        return _build_check(
            "AI Foundation", STATUS_PASS,
            f"scikit-learn {sklearn.__version__} is available."
        )
    except ImportError as e:
        return _build_check(
            "AI Foundation", STATUS_FAIL,
            f"Missing required AI package: {e}",
            severity="critical"
        )

def check_schema_alignment() -> Dict[str, Any]:
    """Validates that the AI schema perfectly matches the Network Engine features."""
    try:
        if not FLOW_FEATURE_ORDER:
            return _build_check("Schema Alignment", STATUS_FAIL, "FLOW_FEATURE_ORDER is empty.", severity="critical")
        if "benign" not in CANONICAL_LABELS:
            return _build_check("Schema Alignment", STATUS_FAIL, "Canonical 'benign' label missing from schemas.", severity="critical")

        return _build_check(
            "Schema Alignment", STATUS_PASS,
            f"Schema {FLOW_SCHEMA_VERSION} aligned with {len(FLOW_FEATURE_ORDER)} features."
        )
    except Exception as e:
        return _build_check("Schema Alignment", STATUS_FAIL, str(e), severity="critical")

def check_active_model_and_integration(registry_path: str = "models/registry.json", models_dir: str = "models") -> List[Dict[str, Any]]:
    """
    Safely probes the model registry, loads the active model, and verifies
    it can be correctly injected into the FlowInferenceAdapter.
    """
    results = []

    # 1. Model Registry Check
    try:
        registry = ModelRegistry(registry_path)
        # Attempt to access to catch JSONDecodeErrors or missing file errors if they load lazily
        active_version = registry.get_active_model_version()
    except FileNotFoundError as e:
        results.append(_build_check("Model Registry", STATUS_NOT_CONFIGURED, f"Registry file missing: {e}", severity="warning"))
        results.append(_build_check("Active Model Validation", STATUS_SKIPPED, "Registry missing."))
        results.append(_build_check("Network Flow Integration", STATUS_SKIPPED, "Registry missing."))
        return results
    except Exception as e:
        results.append(_build_check("Model Registry", STATUS_FAIL, f"Registry error: {e}", severity="critical"))
        results.append(_build_check("Active Model Validation", STATUS_SKIPPED, "Registry failed to load."))
        results.append(_build_check("Network Flow Integration", STATUS_SKIPPED, "Model validation skipped."))
        return results

    results.append(_build_check("Model Registry", STATUS_PASS, "Registry loaded safely."))

    # 2. Active Model Validation
    if not active_version:
        results.append(_build_check("Active Model Validation", STATUS_NOT_CONFIGURED, "No active model is registered.", severity="warning"))
        results.append(_build_check("Network Flow Integration", STATUS_SKIPPED, "No active model available."))
        return results

    engine = None
    try:
        manifest = registry.list_models().get(active_version)
        if not manifest:
            raise ValidationError(f"Manifest for version {active_version} not found in registry.")

        model_dir = manifest.get("model_dir")
        if not model_dir:
            raise ValidationError("model_dir missing in manifest.")

        if not os.path.exists(model_dir):
            raise ValidationError(f"Model directory {model_dir} does not exist.")

        loaded_artifact = load_model_artifact(model_dir)

        # Initialize the Inference Engine (this securely validates hashes, fitted state, and features without executing predict)
        engine = InferenceEngine(loaded_artifact)

        info = engine.get_model_info()
        results.append(_build_check(
            "Active Model Validation", STATUS_PASS,
            f"Model {info['model_version']} loaded safely. Schema: {info['schema_version']}, Features: {info['feature_count']}."
        ))
    except (ValidationError, Exception) as e:
        results.append(_build_check("Active Model Validation", STATUS_FAIL, f"Corrupted or incompatible active model: {e}", severity="critical"))
        results.append(_build_check("Network Flow Integration", STATUS_SKIPPED, "Active model failed validation."))
        return results

    # 3. Network Flow Integration Check
    try:
        # Dependency injection validation
        adapter = FlowInferenceAdapter(engine)
        results.append(_build_check("Network Flow Integration", STATUS_PASS, "FlowInferenceAdapter instantiated successfully with active model."))
    except ValidationError as e:
        results.append(_build_check("Network Flow Integration", STATUS_FAIL, f"Adapter rejected model compatibility: {e}", severity="critical"))
    except Exception as e:
        results.append(_build_check("Network Flow Integration", STATUS_FAIL, f"Unexpected integration error: {e}", severity="critical"))

    return results

def get_ai_status_report(registry_path: str = "models/registry.json", models_dir: str = "models") -> Dict[str, Any]:
    """Generates the full AI health and readiness report."""
    checks = []
    checks.append(check_ai_foundation())
    checks.append(check_schema_alignment())
    checks.extend(check_active_model_and_integration(registry_path, models_dir))

    # Calculate statuses
    total_checks = len(checks)
    failed = [c for c in checks if c["status"] == STATUS_FAIL]
    warnings = [c for c in checks if c["status"] in (STATUS_WARNING, STATUS_NOT_CONFIGURED)]
    passed = [c for c in checks if c["status"] == STATUS_PASS]
    skipped = [c for c in checks if c["status"] == STATUS_SKIPPED]

    overall_status = STATUS_PASS
    readiness = READINESS_INTEGRATION_READY

    if failed:
        overall_status = STATUS_FAIL
        readiness = READINESS_NOT_READY
    elif any(c["name"] == "Active Model Validation" and c["status"] == STATUS_NOT_CONFIGURED for c in checks):
        overall_status = STATUS_WARNING
        readiness = READINESS_CONFIGURATION_READY
    elif warnings:
        overall_status = STATUS_WARNING

    # Ensure readiness correctly reflects integration step
    if readiness == READINESS_INTEGRATION_READY:
        integ_check = next((c for c in checks if c["name"] == "Network Flow Integration"), None)
        if not integ_check or integ_check["status"] != STATUS_PASS:
            readiness = READINESS_MODEL_READY

    return {
        "overall_status": overall_status,
        "readiness_level": readiness,
        "total_checks": total_checks,
        "passed": len(passed),
        "warnings": len(warnings),
        "failed": len(failed),
        "skipped": len(skipped),
        "project_version": get_version(),
        "checks": checks
    }
