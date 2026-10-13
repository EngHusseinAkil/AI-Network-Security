"""
Domain-specific exceptions for alerts.
"""

from utils.exceptions import ApplicationError

class AlertValidationError(ApplicationError):
    """Raised when an alert object violates domain constraints or invalid state transitions occur."""
    def __init__(self, message: str, details=None):
        super().__init__(message, "ALERT_VALIDATION_ERROR", details)

class PolicyConfigurationError(ApplicationError):
    """Raised when alert policy thresholds are contradictory or invalid."""
    def __init__(self, message: str, details=None):
        super().__init__(message, "POLICY_CONFIG_ERROR", details)
