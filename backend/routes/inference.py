"""
Inference API Routes.
"""
import logging
from flask import Blueprint, request, current_app

from backend.responses import build_success_response
from backend.errors.exceptions import RequestValidationError
from utils.exceptions import ValidationError as CoreValidationError
from backend.schemas.inference import validate_single_flow_inference_request, validate_batch_flow_inference_request
from backend.security import rate_limit

logger = logging.getLogger(__name__)

inference_bp = Blueprint('inference', __name__)

@inference_bp.route('/flow', methods=['POST'])
@rate_limit('RATE_LIMIT_INFERENCE_SINGLE')
def infer_flow():
    """
    Accepts exactly one flow feature object and returns a prediction.
    """
    if not request.is_json:
        from werkzeug.exceptions import UnsupportedMediaType
        raise UnsupportedMediaType("Content-Type must be application/json")

    try:
        payload = request.get_json()
    except Exception:
        # Malformed JSON
        raise RequestValidationError("Malformed JSON body.")

    # 1. Validation
    try:
        safe_features = validate_single_flow_inference_request(payload)
    except CoreValidationError as e:
        # Wrap in API-level validation error for proper 400 routing
        raise RequestValidationError(str(e))

    # 2. Prediction
    deps = current_app.extensions['dependencies']
    result = deps.inference_service.predict_flow(safe_features)

    # 3. Privacy Logging
    logger.info("Single-flow inference successful. Model: %s, Predicted: %s",
                result.get("model_version"), result.get("predicted_canonical_label"))

    # 4. Success Response
    return build_success_response(data=result, status_code=200)

@inference_bp.route('/flows', methods=['POST'])
@rate_limit('RATE_LIMIT_INFERENCE_BATCH')
def infer_batch_flows():
    """
    Accepts a batch of flow feature objects and returns their predictions.
    All-or-nothing validation strategy.
    """
    if not request.is_json:
        from werkzeug.exceptions import UnsupportedMediaType
        raise UnsupportedMediaType("Content-Type must be application/json")

    try:
        payload = request.get_json()
    except Exception:
        raise RequestValidationError("Malformed JSON body.")

    # 1. Validation
    try:
        max_batch = current_app.config.get('MAX_INFERENCE_BATCH_SIZE', 100)
        safe_batch = validate_batch_flow_inference_request(payload, max_batch_size=max_batch)
    except CoreValidationError as e:
        # Re-wrap any raw util exception into the API wrapper
        raise RequestValidationError(str(e))

    # 2. Prediction
    deps = current_app.extensions['dependencies']
    result = deps.inference_service.predict_flows(safe_batch)

    # 3. Logging
    logger.info("Batch-flow inference successful. Batch size: %d, Model: %s",
                result.get("count"), result.get("model_version"))

    return build_success_response(data=result, status_code=200)
