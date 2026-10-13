"""
Centralized Error Handlers.
"""
import logging
from flask import Flask, request
from werkzeug.exceptions import HTTPException, BadRequest, RequestEntityTooLarge, UnsupportedMediaType, NotFound, MethodNotAllowed

from backend.responses import build_error_response
from backend.errors.exceptions import ApiError
from utils.exceptions import ValidationError

logger = logging.getLogger(__name__)

def is_api_request():
    """Checks if the request should receive an API response."""
    return request.path.startswith('/api/')

def register_handlers(app: Flask):
    """Register error handlers on the Flask app."""

    @app.errorhandler(ApiError)
    def handle_api_error(error: ApiError):
        if is_api_request():
            return build_error_response(error.code, error.message, details=error.details, status_code=error.status_code)
        # Fallback if somehow raised outside API context
        return error.message, error.status_code

    @app.errorhandler(ValidationError)
    def handle_project_validation_error(error: ValidationError):
        if is_api_request():
            return build_error_response(error.error_code, error.message, details=error.details, status_code=400)
        return error.message, 400

    @app.errorhandler(BadRequest)
    def handle_bad_request(error: BadRequest):
        if is_api_request():
            return build_error_response("BAD_REQUEST", "Malformed request data or invalid JSON.", status_code=400)
        return error.get_response()

    @app.errorhandler(NotFound)
    def handle_not_found(error: NotFound):
        if is_api_request():
            return build_error_response("NOT_FOUND", "The requested endpoint does not exist.", status_code=404)
        return error.get_response()

    @app.errorhandler(MethodNotAllowed)
    def handle_method_not_allowed(error: MethodNotAllowed):
        if is_api_request():
            return build_error_response("METHOD_NOT_ALLOWED", "The method is not allowed for the requested URL.", status_code=405)
        return error.get_response()

    @app.errorhandler(RequestEntityTooLarge)
    def handle_entity_too_large(error: RequestEntityTooLarge):
        if is_api_request():
            return build_error_response("PAYLOAD_TOO_LARGE", "The request payload exceeds the maximum allowed size.", status_code=413)
        return error.get_response()

    @app.errorhandler(UnsupportedMediaType)
    def handle_unsupported_media_type(error: UnsupportedMediaType):
        if is_api_request():
            return build_error_response("UNSUPPORTED_MEDIA_TYPE", "The request Content-Type is not supported.", status_code=415)
        return error.get_response()

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        # We don't want to swallow HTTPExceptions natively supported by Flask if not mapped above
        if isinstance(error, HTTPException):
            if is_api_request():
                # We can map generic HTTP exceptions to JSON
                return build_error_response(
                    "HTTP_ERROR",
                    error.description or "An HTTP error occurred.",
                    status_code=error.code
                )
            return error.get_response()

        logger.exception("Unexpected internal server error: %s", str(error))
        if is_api_request():
            return build_error_response("INTERNAL_ERROR", "An unexpected internal error occurred.", status_code=500)
        return "Internal Server Error", 500
