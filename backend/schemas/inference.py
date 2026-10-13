"""
Inference Request Schema Validation.
"""
from typing import Dict, Any, List
import math
from utils.exceptions import ValidationError
from network.features import FLOW_FEATURE_ORDER

def _field_validation_error(message: str, field: str, reason: str) -> ValidationError:
    return ValidationError(
        message,
        details={"field": field, "reason": reason},
    )


def _batch_item_error_message(index: int, error: ValidationError) -> str:
    field = error.details.get("field")
    reason = error.details.get("reason")
    if field and reason:
        return f"Validation failed for item in batch: flows[{index}].{field} {reason}."

    missing_fields = error.details.get("missing_fields")
    if missing_fields:
        paths = ", ".join(f"flows[{index}].{field}" for field in missing_fields)
        return f"Validation failed for item in batch: required fields are missing: {paths}."

    return f"Validation failed for item in batch: flows[{index}]: {error.message}"


def validate_single_flow_inference_request(payload: Any) -> Dict[str, float]:
    """
    Strictly validates that the request JSON body contains exactly the required flow features,
    and no forbidden fields, arrays, missing, extra, string, null, nan, inf, boolean, or label values.
    Returns a float dictionary safe for the AI engine.
    """
    if payload is None:
        raise ValidationError("Missing JSON body.")

    if not isinstance(payload, dict):
        raise ValidationError("Payload must be a JSON object, not an array or primitive.")

    provided_keys = set(payload.keys())
    expected_keys = set(FLOW_FEATURE_ORDER)

    # 1. Reject label injection
    if "label" in provided_keys:
        raise _field_validation_error(
            "Field 'label' is forbidden in inference requests.",
            "label",
            "is forbidden",
        )

    # 2. Reject payload/packet metadata (not part of FLOW_FEATURE_ORDER, handled by missing/extra checks)

    # 3. Exact field matching
    missing = expected_keys - provided_keys
    if missing:
        sorted_missing = sorted(missing)
        raise ValidationError(
            f"Missing required fields: {sorted_missing}",
            details={"missing_fields": sorted_missing},
        )

    extra = provided_keys - expected_keys
    if extra:
        raise ValidationError(f"Unexpected extra fields found: {sorted(list(extra))}")

    # 4. Strict Type and Sanity checking
    safe_features = {}
    for key in FLOW_FEATURE_ORDER:
        val = payload[key]

        # Must be int or float, not bool (bool is subclass of int)
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            raise _field_validation_error(
                f"Field '{key}' has invalid type {type(val).__name__}. Expected integer or float.",
                key,
                "must be an integer or float",
            )

        # No NaN or Inf
        if math.isnan(val) or math.isinf(val):
            raise _field_validation_error(
                f"Field '{key}' contains NaN or Infinity.",
                key,
                "must be finite",
            )

        # We enforce type conversion safely
        safe_features[key] = float(val)

    # Protocol encoding schema validation (from ai.schema)
    proto_enc = safe_features["protocol_enc"]
    if proto_enc not in (0.0, 1.0, 2.0, 3.0):
        raise _field_validation_error(
            f"Unsupported protocol_enc: {proto_enc}",
            "protocol_enc",
            "is unsupported",
        )

    # Direction encoding schema validation
    dir_enc = safe_features["direction_enc"]
    if dir_enc not in (0.0, 1.0, 2.0, 3.0, 4.0):
        raise _field_validation_error(
            f"Unsupported direction_enc: {dir_enc}",
            "direction_enc",
            "is unsupported",
        )

    # Durations and counts cannot be negative in flow
    if safe_features["duration"] < 0:
        raise _field_validation_error(
            "duration cannot be negative.", "duration", "cannot be negative"
        )
    if safe_features["packet_count"] < 0:
        raise _field_validation_error(
            "packet_count cannot be negative.", "packet_count", "cannot be negative"
        )
    if safe_features["byte_count"] < 0:
        raise _field_validation_error(
            "byte_count cannot be negative.", "byte_count", "cannot be negative"
        )
    if safe_features["min_packet_size"] < 0:
        raise _field_validation_error(
            "min_packet_size cannot be negative.", "min_packet_size", "cannot be negative"
        )
    if safe_features["max_packet_size"] < 0:
        raise _field_validation_error(
            "max_packet_size cannot be negative.", "max_packet_size", "cannot be negative"
        )
    if safe_features["avg_packet_size"] < 0:
        raise _field_validation_error(
            "avg_packet_size cannot be negative.", "avg_packet_size", "cannot be negative"
        )

    return safe_features

def validate_batch_flow_inference_request(payload: Any, max_batch_size: int = 100) -> List[Dict[str, float]]:
    """
    Strictly validates a batch of flow inference requests.
    Enforces 'flows' wrapper, array bounds, and atomic item validation.
    Returns a list of safe dictionaries.
    """
    if payload is None:
        raise ValidationError("Missing JSON body.")

    if not isinstance(payload, dict):
        raise ValidationError("Batch payload must be a JSON object, not an array or primitive.")

    provided_keys = set(payload.keys())
    if provided_keys != {"flows"}:
        raise ValidationError("Batch payload must contain exactly the 'flows' key.")

    flows = payload["flows"]
    if not isinstance(flows, list):
        raise ValidationError("The 'flows' value must be an array.")

    if len(flows) == 0:
        from backend.errors.exceptions import RequestValidationError
        raise RequestValidationError("Empty batch.", details={"batch_size_invalid": True})

    if len(flows) > max_batch_size:
        from backend.errors.exceptions import RequestValidationError
        # It's stated we can return 400 with a stable error.
        raise RequestValidationError("Batch size exceeded limit.", details={"batch_size_exceeded": True, "limit": max_batch_size})

    safe_batch = []
    for idx, item in enumerate(flows):
        try:
            safe_item = validate_single_flow_inference_request(item)
            safe_batch.append(safe_item)
        except ValidationError as e:
            from backend.errors.exceptions import RequestValidationError
            # Safely report index without echoing payload
            raise RequestValidationError(
                _batch_item_error_message(idx, e),
                details={"item_index": idx, "reason": e.message},
            ) from e

    return safe_batch
