"""
Centralized custom exception hierarchy for the AI Network Security Platform.
"""
from typing import Any, Dict, Optional

class ApplicationError(Exception):
    """Base class for all project-specific exceptions."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "APP_ERROR"
        self.details = details or {}

    def __str__(self) -> str:
        """Returns a clean string representation of the error."""
        return f"[{self.error_code}] {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        """Converts the exception to a dictionary for API responses."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details
        }

class ConfigurationError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFIG_ERROR", details)

class ValidationError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "VALIDATION_ERROR", details)

class FileOperationError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "FILE_OP_ERROR", details)

class NotFoundError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "NOT_FOUND", details)

class ConflictError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFLICT", details)

class DatabaseError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "DATABASE_ERROR", details)

class NetworkError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "NETWORK_ERROR", details)

class AIModelError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "AI_MODEL_ERROR", details)

class SecurityError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "SECURITY_ERROR", details)

class AuthenticationError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "AUTH_ERROR", details)

class AuthorizationError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "FORBIDDEN", details)

class APIError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "API_ERROR", details)

class MitigationError(ApplicationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "MITIGATION_ERROR", details)
