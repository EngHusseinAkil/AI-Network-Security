"""
API-Specific Exception Hierarchy.
"""
from typing import Optional, Dict, Any

class ApiError(Exception):
    """Base class for all API exceptions."""
    def __init__(self, message: str, code: str, status_code: int = 500, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}

class RequestValidationError(ApiError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "VALIDATION_ERROR", 400, details)

class ResourceNotFoundError(ApiError):
    def __init__(self, message: str = "The requested resource was not found.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "NOT_FOUND", 404, details)

class MethodNotAllowedApiError(ApiError):
    def __init__(self, message: str = "Method not allowed for this resource.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "METHOD_NOT_ALLOWED", 405, details)

class ModelUnavailableError(ApiError):
    def __init__(self, message: str = "No active AI model is currently available to process requests.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "MODEL_UNAVAILABLE", 503, details)

class ModelCompatibilityError(ApiError):
    def __init__(self, message: str = "The active model is incompatible with the request.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "MODEL_INCOMPATIBLE", 400, details)

class ServiceUnavailableError(ApiError):
    def __init__(self, message: str = "The requested service is temporarily unavailable.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "SERVICE_UNAVAILABLE", 503, details)

class ConflictApiError(ApiError):
    def __init__(self, message: str = "A conflict occurred with the current state of the resource.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFLICT", 409, details)

class InternalApiError(ApiError):
    def __init__(self, message: str = "An unexpected internal error occurred.", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "INTERNAL_ERROR", 500, details)
