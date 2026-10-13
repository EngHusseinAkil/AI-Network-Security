"""
Model Service for the Backend API.
Provides read-only access to model registry state without loading estimators into memory.
"""
import os
import json
import logging
from typing import Dict, Any

from utils.exceptions import ValidationError
from ai.model_registry import ModelRegistry
from ai.constants import FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from network.features import FLOW_FEATURE_ORDER

logger = logging.getLogger(__name__)

class ModelService:
    """Service to interact with the model registry metadata safely."""

    def __init__(self, registry_path: str = "models/registry.json"):
        self.registry_path = registry_path

    def _get_registry(self) -> ModelRegistry:
        return ModelRegistry(self.registry_path)

    def get_models(self) -> Dict[str, Any]:
        """Lists registered models returning strictly safe metadata."""
        try:
            registry = self._get_registry()
            models_data = registry.list_models()
            active_version = registry.get_active_model_version()
        except FileNotFoundError:
            # Registry does not exist, consider it not configured
            return {"models": [], "count": 0, "registry_status": "not_configured"}
        except Exception as e:
            logger.error("Failed to read model registry: %s", e)
            return {"models": [], "count": 0, "registry_status": "error"}

        safe_models = []
        for version, meta in models_data.items():
            safe_models.append({
                "model_version": version,
                "schema_version": meta.get("schema_version", "unknown"),
                "is_testing_fallback_split": meta.get("is_testing_fallback_split", False),
                "evaluated_row_count": meta.get("evaluated_row_count", 0),
                "active": version == active_version
            })

        return {
            "models": safe_models,
            "count": len(safe_models),
            "registry_status": "configured"
        }

    def get_active_model(self) -> Dict[str, Any]:
        """Inspects the active model metadata without deserializing the joblib estimator."""
        try:
            registry = self._get_registry()
            active_version = registry.get_active_model_version()
        except Exception as e:
            logger.error("Failed to read active model pointer: %s", e)
            return {"active": False, "model": None, "status": "error"}

        if not active_version:
            return {"active": False, "model": None, "status": "not_configured"}

        try:
            manifest = registry.list_models().get(active_version)
            if not manifest:
                raise ValidationError(f"Manifest for version {active_version} missing in registry dict.")

            model_dir = manifest.get("model_dir")
            if not model_dir or not os.path.exists(model_dir):
                raise ValidationError("Model directory is missing or deleted from filesystem.")

            # We inspect the metadata.json directly rather than calling load_model_artifact,
            # which would inadvertently trigger joblib.load() and deserialize the estimator.
            metadata_path = os.path.join(model_dir, "metadata.json")
            if not os.path.exists(metadata_path):
                raise ValidationError("metadata.json missing in model directory.")

            with open(metadata_path, "r") as f:
                metadata_export = json.load(f)

            schema_meta = metadata_export.get("schema_metadata", {})
            model_meta = metadata_export.get("model_metadata", {})

            # Quick compatibility check based on raw metadata
            is_compatible = (
                schema_meta.get("schema_type") == "flow" and
                schema_meta.get("schema_version") == FLOW_SCHEMA_VERSION and
                model_meta.get("ordered_feature_names") == FLOW_FEATURE_ORDER
            )

            safe_data = {
                "active": True,
                "status": "ready" if is_compatible else "incompatible",
                "model": {
                    "model_version": metadata_export.get("model_version", active_version),
                    "model_family": model_meta.get("estimator_class", "unknown"),
                    "schema_version": schema_meta.get("schema_version", "unknown"),
                    "preprocessing_version": schema_meta.get("preprocessing_version", "unknown"),
                    "feature_count": len(model_meta.get("ordered_feature_names", [])),
                    "supported_labels": list(model_meta.get("label_encoding_map", {}).keys()),
                    "benign_class_available": "benign" in model_meta.get("label_encoding_map", {}),
                    "compatibility_status": "compatible" if is_compatible else "incompatible_schema_or_features",
                    "creation_time_utc": metadata_export.get("creation_time_utc"),
                    "security_disclaimer": "This metadata is parsed securely without joblib execution."
                }
            }
            return safe_data

        except Exception as e:
            logger.error("Active model validation failed safely: %s", e)
            # If the registry pointer is corrupt, we still return a valid envelope but false/error.
            # The prompt instructs: "When registry state points to an unknown or corrupt active version:
            # return a safe 503 health-style response or mapped service-unavailable error..."
            # For the endpoint to map it to 503, we can raise an ApiError, or handle it via status field.
            # Let's raise ServiceUnavailableError which the route can catch, or we can just pass the error
            # so the route sees it as a ServiceUnavailable condition. We will raise a ValidationError so the
            # global error handler maps it to 400? Wait, the prompt says:
            # "return a safe 503 health-style response or mapped service-unavailable error"
            from backend.errors.exceptions import ServiceUnavailableError
            raise ServiceUnavailableError("The active model is unavailable or its metadata is corrupted.") from e
