"""
AI Offline Inference Interface.

Provides a secure boundary for generating predictions from loaded models.
Strictly isolated from network traffic capture, blocking logic, and threat log storage.
"""

import math
import time
from typing import Dict, Any, List, Union

import numpy as np

from utils.exceptions import ValidationError
from network.features import FLOW_FEATURE_ORDER
from ai.constants import CANONICAL_LABELS
from ai.model_persistence import load_model_artifact
from ai.model_registry import ModelRegistry


class InferenceEngine:
    """
    Secure wrapper around a validated estimator.
    Read-only after initialization.
    """

    def __init__(self, loaded_artifact: Dict[str, Any]):
        """
        Initializes the engine from a previously loaded and validated artifact dictionary.
        Do not call this directly with an untrusted dictionary. Use factory methods.
        """
        self._estimator = loaded_artifact.get("estimator")
        if not self._estimator:
            raise ValidationError("Inference engine requires a valid estimator.")

        if not hasattr(self._estimator, "predict_proba"):
            raise ValidationError("Inference engine currently requires probability support (predict_proba).")

        self._metadata = loaded_artifact.get("metadata", {})
        model_meta = self._metadata.get("model_metadata", {})

        self._model_version = self._metadata.get("model_version", "unknown")
        self._model_family = model_meta.get("model_family", "unknown")
        self._schema_version = self._metadata.get("schema_metadata", {}).get("schema_version")
        self._preprocessing_version = self._metadata.get("schema_metadata", {}).get("preprocessing_version")

        self._ordered_features = model_meta.get("ordered_feature_names", FLOW_FEATURE_ORDER)
        self._feature_count = len(self._ordered_features)

        # Mapping definition (canonical name -> internal index)
        self._label_encoding = model_meta.get("label_encoding_map", {})
        if not self._label_encoding:
            raise ValidationError("Missing label encoding map in loaded artifact.")

        self._index_to_label = {v: k for k, v in self._label_encoding.items()}

        # Pre-resolve the baseline negative class for deterministic risk scoring
        self._benign_encoded = self._label_encoding.get("benign")
        if self._benign_encoded is None:
            raise ValidationError("The canonical 'benign' label must exist in the model's mapping for risk scoring.")

        # Estimator classes may not perfectly match canonical indexes if classes were missing during training.
        # However, check_is_fitted and compatibility validation ensures the estimator matches.
        # We store the column mapping: canonical string -> probability column index
        self._class_prob_columns = {}
        for col_idx, encoded_class in enumerate(self._estimator.classes_):
            canonical_name = self._index_to_label.get(encoded_class)
            if canonical_name is not None:
                self._class_prob_columns[canonical_name] = col_idx

    @classmethod
    def from_artifact(cls, artifact_dir: str) -> "InferenceEngine":
        """
        Safely loads a model from a trusted artifact directory path.
        Enforces integrity validation (SHA-256) before returning the engine.
        """
        artifact = load_model_artifact(artifact_dir)
        return cls(artifact)

    @classmethod
    def from_active_registry(cls, registry_path: str) -> "InferenceEngine":
        """
        Safely loads the currently active model from a registry.
        """
        registry = ModelRegistry(registry_path)
        active_version = registry.get_active_model_version()
        if not active_version:
            raise ValidationError("No active model is set in the registry.")

        models = registry.list_models()
        if active_version not in models:
            raise ValidationError(f"Active model version '{active_version}' is not registered.")

        model_dir = models[active_version].get("model_dir")
        if not model_dir:
            raise ValidationError(f"Missing directory for active model '{active_version}'.")

        return cls.from_artifact(model_dir)

    def get_model_info(self) -> Dict[str, Any]:
        """Returns safe, lightweight diagnostic metadata."""
        return {
            "model_version": self._model_version,
            "model_family": self._model_family,
            "schema_version": self._schema_version,
            "preprocessing_version": self._preprocessing_version,
            "feature_count": self._feature_count
        }

    def supports_canonical_label(self, label: str) -> bool:
        """
        Returns True if the underlying model is mapped to predict
        or report probabilities for the specified canonical label.
        """
        return label in self._class_prob_columns

    def validate_runtime_compatibility(self, expected_schema: str, expected_feature_count: int) -> bool:
        """
        Safely validates whether the loaded engine matches the runtime expectations
        without exposing private metadata structures.
        """
        if self._schema_version != expected_schema:
            return False
        if self._feature_count != expected_feature_count:
            return False
        return True

    def _validate_and_transform_input(self, features: Union[Dict[str, float], List[float]]) -> List[float]:
        """
        Transforms and strictly validates a single input into a numerical vector.
        """
        vector = []
        if isinstance(features, dict):
            # Check for illegal label injection
            if "label" in features:
                raise ValidationError("Labels cannot be passed into feature inference dictionaries.")

            # Reject packet-specific structures or missing fields implicitly by demanding EXACT flow features
            if len(features) != self._feature_count:
                raise ValidationError(f"Feature dictionary length ({len(features)}) does not match required count ({self._feature_count}).")

            for feature_name in self._ordered_features:
                if feature_name not in features:
                    raise ValidationError(f"Missing required feature: {feature_name}")
                val = features[feature_name]
                if not isinstance(val, (int, float)):
                    raise ValidationError(f"Feature '{feature_name}' must be numeric.")
                if math.isnan(val) or math.isinf(val):
                    raise ValidationError(f"Feature '{feature_name}' contains NaN or Infinity.")
                vector.append(float(val))
        elif isinstance(features, list):
            if len(features) != self._feature_count:
                raise ValidationError(f"Feature vector length ({len(features)}) does not match required count ({self._feature_count}).")
            for i, val in enumerate(features):
                if not isinstance(val, (int, float)):
                    raise ValidationError(f"Feature at index {i} must be numeric.")
                if math.isnan(val) or math.isinf(val):
                    raise ValidationError(f"Feature at index {i} contains NaN or Infinity.")
                vector.append(float(val))
        else:
            raise ValidationError("Features must be a dictionary or numerical list.")

        return vector

    def predict_one(self, features: Union[Dict[str, float], List[float]]) -> Dict[str, Any]:
        """Predicts a single record."""
        return self.predict_batch([features])[0]

    def predict_batch(self, batch_features: List[Union[Dict[str, float], List[float]]]) -> List[Dict[str, Any]]:
        """
        Processes an entire batch sequentially for validation,
        then performs a single optimized estimator prediction call.
        """
        if not batch_features:
            return []

        # 1. Validation
        X_matrix = []
        for row in batch_features:
            X_matrix.append(self._validate_and_transform_input(row))

        # 2. Prediction (Latency Captured)
        start_time = time.perf_counter()
        encoded_predictions = self._estimator.predict(X_matrix)
        probability_matrix = self._estimator.predict_proba(X_matrix)
        end_time = time.perf_counter()

        total_latency = end_time - start_time
        per_row_latency = total_latency / len(batch_features)

        # 3. Output Packaging
        results = []
        for i, (encoded_pred, prob_row) in enumerate(zip(encoded_predictions, probability_matrix)):

            # Map canonical probabilites safely based on exact estimator columns
            class_probs = {}
            for canonical_name, col_idx in self._class_prob_columns.items():
                class_probs[canonical_name] = float(prob_row[col_idx])

            predicted_label = self._index_to_label.get(encoded_pred, "unknown")
            confidence = class_probs.get(predicted_label, 0.0)

            # Risk Score: 1.0 - P(benign)
            # Represents the sum probability of all non-benign classes (including unknown if present in model)
            p_benign = class_probs.get("benign", 0.0)
            risk_score = 1.0 - p_benign

            # Clamp strictly to [0.0, 1.0] for floating point safety
            risk_score = max(0.0, min(1.0, risk_score))

            results.append({
                "predicted_encoded_class": int(encoded_pred),
                "predicted_canonical_label": predicted_label,
                "confidence_score": confidence,
                "risk_score": risk_score,
                "class_probabilities": class_probs,
                "model_version": self._model_version,
                "model_family": self._model_family,
                "schema_version": self._schema_version,
                "preprocessing_version": self._preprocessing_version,
                "feature_count": self._feature_count,
                "inference_latency": {
                    "total_batch_seconds": total_latency,
                    "average_seconds_per_row": per_row_latency
                },
                "explanation_metadata": {
                    "interpreted_threat": risk_score > 0.5,
                    "unknown_class_behavior": "Treated as non-benign (suspicious) risk contribution."
                },
                "disclaimer": "Risk scores denote model confidence, not confirmed severity. Values generated locally."
            })

        return results
