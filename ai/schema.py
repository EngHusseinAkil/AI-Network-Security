"""
Feature Schema Contract.

Establishes strict validation rules and versioned schemas between the
runtime Network Engine and the AI Engine. It uses authoritative feature
definitions from `network.features`.
"""

from typing import Dict, List, Any, Union
import math

from network.features import PACKET_FEATURE_ORDER, FLOW_FEATURE_ORDER
from ai.constants import PACKET_SCHEMA_VERSION, FLOW_SCHEMA_VERSION, CANONICAL_LABELS
from utils.exceptions import ValidationError


def _validate_common_dict(features: Dict[str, Any], expected_order: List[str], strict: bool) -> None:
    """Internal helper to validate a dictionary of features."""
    if not isinstance(features, dict):
        raise ValidationError("Features must be provided as a dictionary.")

    provided_keys = set(features.keys())
    expected_keys = set(expected_order)

    # Check for missing features
    missing = expected_keys - provided_keys
    if missing:
        raise ValidationError(f"Missing required features: {sorted(list(missing))}")

    # Check for extra features
    if strict:
        extra = provided_keys - expected_keys
        if extra:
            raise ValidationError(f"Unexpected extra features found: {sorted(list(extra))}")

    # Validate value types and sanity (NaN/Inf)
    for key in expected_order:
        val = features[key]
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            raise ValidationError(f"Feature '{key}' has invalid type {type(val).__name__}. Expected int or float.")
        if math.isnan(val) or math.isinf(val):
            raise ValidationError(f"Feature '{key}' contains NaN or infinite value: {val}")


def validate_packet_feature_dict(features: Dict[str, Any], strict: bool = True) -> None:
    """
    Validates a packet feature dictionary against the authoritative schema.

    Port -1 Semantics:
    Source or destination port `-1` is the authoritative runtime sentinel emitted by
    `network/features.py` for portless protocols (e.g., ICMP).

    Database Persistence Sentinel:
    The database exporter currently uses `0` for missing ports only to satisfy
    the current non-nullable database schema. This `0` is for persistence only
    and is not the runtime feature value.

    The AI layer must not interpret `-1` or `0` as real observed transport-layer ports.
    """
    _validate_common_dict(features, PACKET_FEATURE_ORDER, strict)


def validate_flow_feature_dict(features: Dict[str, Any], strict: bool = True) -> None:
    """
    Validates a flow feature dictionary against the authoritative schema.
    """
    _validate_common_dict(features, FLOW_FEATURE_ORDER, strict)


def validate_feature_vector(vector: List[Union[int, float]], expected_length: int) -> None:
    """
    Validates an ordered feature vector.
    Checks for correct length and numerical validity (no NaN/Inf).
    """
    if not isinstance(vector, list):
        raise ValidationError("Feature vector must be a list.")

    if len(vector) != expected_length:
        raise ValidationError(f"Feature vector length mismatch. Expected {expected_length}, got {len(vector)}")

    for idx, val in enumerate(vector):
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            raise ValidationError(f"Vector item at index {idx} has invalid type {type(val).__name__}. Expected int or float.")
        if math.isnan(val) or math.isinf(val):
            raise ValidationError(f"Vector item at index {idx} contains NaN or infinite value: {val}")


def validate_feature_order(provided_order: List[str], expected_order: List[str]) -> None:
    """
    Validates that a provided list of feature names exactly matches the expected order.
    """
    if not isinstance(provided_order, list):
        raise ValidationError("Provided order must be a list of strings.")

    if provided_order != expected_order:
        raise ValidationError("Feature order mismatch. The provided order does not match the authoritative schema.")


def validate_canonical_label(label: str) -> None:
    """
    Validates that a label is within the canonical label foundation.
    """
    if label not in CANONICAL_LABELS:
        raise ValidationError(f"Label '{label}' is not supported. Supported labels are: {CANONICAL_LABELS}")


def get_packet_schema_metadata() -> Dict[str, Any]:
    """
    Returns safe, versioned metadata about the packet feature schema.
    """
    return {
        "schema_name": "packet_features",
        "schema_version": PACKET_SCHEMA_VERSION,
        "ordered_features": list(PACKET_FEATURE_ORDER),
        "feature_count": len(PACKET_FEATURE_ORDER),
        "encoding_mappings": {
            "protocol_enc": {"OTHER": 0, "TCP": 1, "UDP": 2, "ICMP": 3},
            "direction_enc": {"unknown": 0, "internal": 1, "outbound": 2, "inbound": 3, "external": 4}
        },
        "missing_value_policy": "Missing ports evaluate to -1. Missing general features evaluate to 0.0.",
        "port_semantics": "Runtime feature sentinel is -1 for portless protocols. DB persistence uses 0 due to non-nullable schema. AI must not interpret -1 or 0 as observed ports.",
        "source_module": "network.features"
    }


def get_flow_schema_metadata() -> Dict[str, Any]:
    """
    Returns safe, versioned metadata about the flow feature schema.
    """
    return {
        "schema_name": "flow_features",
        "schema_version": FLOW_SCHEMA_VERSION,
        "ordered_features": list(FLOW_FEATURE_ORDER),
        "feature_count": len(FLOW_FEATURE_ORDER),
        "encoding_mappings": {
            "protocol_enc": {"OTHER": 0, "TCP": 1, "UDP": 2, "ICMP": 3},
            "direction_enc": {"unknown": 0, "internal": 1, "outbound": 2, "inbound": 3, "external": 4}
        },
        "missing_value_policy": "Missing features evaluate to 0.0.",
        "port_semantics": "Runtime feature sentinel is -1 for portless protocols. DB persistence uses 0 due to non-nullable schema. AI must not interpret -1 or 0 as observed ports.",
        "source_module": "network.features"
    }
