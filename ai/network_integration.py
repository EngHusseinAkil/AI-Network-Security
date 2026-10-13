"""
Network Flow-to-AI Integration Boundary.

Connects completed Network Engine flow records to the offline InferenceEngine.
Provides safe validation, deterministic feature extraction, strict error isolation,
and privacy-preserving prediction results without modifying system state.
"""

import math
import logging
import hashlib
from typing import Dict, Any, List, Union

from network.metadata import FlowMetadata
from network.features import extract_flow_features, FLOW_FEATURE_ORDER
from ai.inference import InferenceEngine
from utils.exceptions import ValidationError

logger = logging.getLogger(__name__)

class FlowInferenceAdapter:
    """
    Adapter bridging the Network Engine's completed flows with the AI Inference Engine.
    Operates as a pure, deterministic, read-only transformation boundary.
    """

    def __init__(self, engine: InferenceEngine):
        """
        Initializes the adapter using an injected InferenceEngine.
        Validates model compatibility requirements before allowing predictions.
        """
        if not isinstance(engine, InferenceEngine):
            raise ValidationError("Adapter requires a valid InferenceEngine instance.")

        self._engine = engine

        # Validate schema and feature count compatibilities using public API
        if not self._engine.validate_runtime_compatibility("1.0.0", len(FLOW_FEATURE_ORDER)):
            raise ValidationError("Incompatible AI schema version or feature count for flow integration.")

        # Validate canonical label compatibility
        if not self._engine.supports_canonical_label("benign"):
            raise ValidationError("Active model is incompatible: canonical 'benign' class is absent.")

        info = self._engine.get_model_info()
        logger.info(
            "FlowInferenceAdapter initialized successfully with model version: %s",
            info.get("model_version")
        )

    def get_integration_status(self) -> Dict[str, Any]:
        """Returns the current readiness and underlying engine metadata."""
        return {
            "status": "ready",
            "model_info": self._engine.get_model_info()
        }

    def _validate_and_extract(self, flow: FlowMetadata) -> Dict[str, float]:
        """
        Validates the completed flow state and invokes authoritative feature extraction.
        Rejects malformed or severely corrupted network states.
        """
        if not isinstance(flow, FlowMetadata):
            raise ValidationError("Input must be a valid FlowMetadata object.")

        # Basic logical bounds checking for a "completed" flow
        if flow.packet_count <= 0:
            raise ValidationError("Flow has zero or negative packet count.")

        if flow.byte_count < 0:
            raise ValidationError("Flow has negative byte count.")

        if flow.duration < 0.0:
            raise ValidationError("Flow has negative duration.")

        if not flow.protocol:
            raise ValidationError("Flow is missing a protocol definition.")

        # Attempt canonical feature extraction via Network Engine
        try:
            features = extract_flow_features(flow)
        except Exception as e:
            raise ValidationError(f"Network Engine feature extraction failed: {str(e)}") from e

        # Sanity check numerical boundaries of the extracted dictionary
        for k, v in features.items():
            if math.isnan(v) or math.isinf(v):
                raise ValidationError(f"Extracted feature '{k}' contains NaN or Infinity.")

        return features

    def predict_completed_flow(self, flow: FlowMetadata) -> Dict[str, Any]:
        """
        Extracts features and generates a prediction for a single completed flow.
        """
        # 1. Validation and Extraction
        features = self._validate_and_extract(flow)

        # 2. Prediction
        try:
            prediction_result = self._engine.predict_one(features)
        except Exception as e:
            logger.error("Inference Engine prediction failed for flow %s", flow.flow_key)
            raise ValidationError(f"Prediction failed: {str(e)}") from e

        # 3. Safe Result Assembly
        return self._format_result(flow, prediction_result)

    def predict_completed_flows(self, flows: List[FlowMetadata]) -> List[Dict[str, Any]]:
        """
        Generates predictions for a batch of completed flows.
        Strict error policy: If any flow fails validation, the entire batch is rejected.
        """
        if not flows:
            return []

        # 1. Strict Batch Validation and Extraction
        batch_features = []
        for i, flow in enumerate(flows):
            try:
                features = self._validate_and_extract(flow)
                batch_features.append(features)
            except Exception as e:
                logger.error("Batch validation failed at index %d (Flow %s): %s", i, getattr(flow, 'flow_key', 'unknown'), str(e))
                raise ValidationError(f"Batch prediction aborted due to invalid flow at index {i}: {str(e)}") from e

        # 2. Batch Prediction
        try:
            prediction_results = self._engine.predict_batch(batch_features)
        except Exception as e:
            logger.error("Inference Engine batch prediction failed for %d flows.", len(flows))
            raise ValidationError(f"Batch prediction failed: {str(e)}") from e

        # 3. Safe Result Assembly
        final_results = []
        for flow, pred_res in zip(flows, prediction_results):
            final_results.append(self._format_result(flow, pred_res))

        return final_results

    def _format_result(self, flow: FlowMetadata, prediction_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Constructs the final secure integration result, safely identifying the flow
        without exposing raw bytes, payloads, or full credentials in the output.
        Pseudonymizes the FlowKey using SHA-256 to protect raw IPs/ports in logs.
        """
        raw_key_str = str(flow.flow_key) if flow.flow_key else "unknown"
        flow_key_hashed = hashlib.sha256(raw_key_str.encode('utf-8')).hexdigest()[:16] if raw_key_str != "unknown" else "unknown"

        return {
            "flow_identifier": flow_key_hashed,
            "prediction": {
                "canonical_label": prediction_result.get("predicted_canonical_label"),
                "confidence_score": prediction_result.get("confidence_score"),
                "risk_score": prediction_result.get("risk_score")
            },
            "integration_status": "success",
            "model_metadata": {
                "model_version": prediction_result.get("model_version"),
                "schema_version": prediction_result.get("schema_version")
            },
            "disclaimer": prediction_result.get("disclaimer", "")
        }
