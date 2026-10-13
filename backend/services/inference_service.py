"""
Inference Service.
Handles lazy thread-safe initialization of the InferenceEngine
and routes validated predictions locally.
"""
import threading
import logging
from typing import Dict, Any, Optional

from utils.exceptions import ValidationError
from backend.errors.exceptions import ServiceUnavailableError
from ai.inference import InferenceEngine
from network.features import FLOW_FEATURE_ORDER

logger = logging.getLogger(__name__)

class InferenceService:
    def __init__(self, registry_path: str = "models/registry.json"):
        """
        Initializes the InferenceService but does NOT load the model immediately.
        """
        self.registry_path = registry_path
        self._engine: Optional[InferenceEngine] = None
        self._lock = threading.Lock()

    def _get_engine(self) -> InferenceEngine:
        """
        Thread-safely initializes and returns the InferenceEngine.
        Raises ServiceUnavailableError if no active model or artifact is corrupt.
        """
        if self._engine is not None:
            return self._engine

        with self._lock:
            # Double check inside the lock
            if self._engine is not None:
                return self._engine

            logger.info("Initializing lazy inference engine from registry path: %s", self.registry_path)
            try:
                self._engine = InferenceEngine.from_active_registry(self.registry_path)
            except ValidationError as e:
                # E.g., no active model, or missing manifest
                logger.error("Failed to lazily load active model: %s", e)
                raise ServiceUnavailableError("model_unavailable: Active model could not be loaded safely.") from e
            except Exception as e:
                logger.error("Unexpected error during active model load: %s", e)
                raise ServiceUnavailableError("model_unavailable: Unexpected initialization failure.") from e

            return self._engine

    def predict_flow(self, safe_features: Dict[str, float]) -> Dict[str, Any]:
        """
        Delegates exactly one validated flow feature dictionary to the engine.
        Raises ServiceUnavailableError if engine is unusable.
        """
        engine = self._get_engine()

        try:
            return engine.predict_one(safe_features)
        except Exception as e:
            logger.exception("Inference failed during predict_one: %s", e)
            raise ServiceUnavailableError("inference_failed: The model encountered an error during inference.") from e

    def get_model_info(self) -> Dict[str, Any]:
        """Return safe active-model metadata, loading lazily when explicitly requested."""
        return self._get_engine().get_model_info()

    def predict_flows(self, safe_features_list: list[Dict[str, float]]) -> Dict[str, Any]:
        """
        Delegates a batch of validated flow feature dictionaries to the engine's predict_batch().
        """
        engine = self._get_engine()

        try:
            normalized_rows = []
            for index, row in enumerate(safe_features_list):
                if type(row) is not dict:
                    raise ValidationError(
                        f"Validated batch row {index} must be a plain dictionary."
                    )
                if set(row) != set(FLOW_FEATURE_ORDER):
                    raise ValidationError(
                        f"Validated batch row {index} does not match the canonical feature schema."
                    )
                normalized_rows.append(
                    {feature: row[feature] for feature in FLOW_FEATURE_ORDER}
                )

            predictions = engine.predict_batch(normalized_rows)
        except Exception as e:
            logger.exception("Inference failed during predict_batch: %s", e)
            raise ServiceUnavailableError("inference_failed: The model encountered an error during batch inference.") from e

        # We can optimize response size by extracting common metadata at the batch level.
        if not predictions:
            return {"count": 0, "predictions": []}

        first = predictions[0]
        batch_meta = {
            "count": len(predictions),
            "model_version": first.get("model_version"),
            "model_family": first.get("model_family"),
            "schema_version": first.get("schema_version"),
            "preprocessing_version": first.get("preprocessing_version"),
            "inference_latency": {
                "total_batch_seconds": first.get("inference_latency", {}).get("total_batch_seconds", 0.0),
                "average_seconds_per_row": first.get("inference_latency", {}).get("average_seconds_per_row", 0.0)
            },
            "disclaimer": first.get("disclaimer"),
            "predictions": []
        }

        for p in predictions:
            batch_meta["predictions"].append({
                "predicted_encoded_class": p.get("predicted_encoded_class"),
                "predicted_canonical_label": p.get("predicted_canonical_label"),
                "confidence_score": p.get("confidence_score"),
                "risk_score": p.get("risk_score"),
                "class_probabilities": p.get("class_probabilities")
            })

        return batch_meta

    # Test hooks
    def inject_engine_for_testing(self, engine: InferenceEngine):
        """Allows tests to skip lazy loading and inject a fake engine."""
        with self._lock:
            self._engine = engine
