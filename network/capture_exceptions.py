# network/capture_exceptions.py
"""Capture-specific exception hierarchy and error category enumeration.

All exceptions are framework‑neutral; they are raised by the capture service
and later mapped to HTTP status codes in the Flask route layer.
"""

from enum import Enum, auto


class CaptureErrorCategory(Enum):
    missing_dependency = auto()
    permission_denied = auto()
    invalid_interface = auto()
    capture_disabled = auto()
    already_running = auto()
    not_running = auto()
    source_initialization_failed = auto()
    capture_failed = auto()
    queue_overflow = auto()
    packet_limit_reached = auto()
    duration_limit_reached = auto()
    stop_timeout = auto()
    resource_exhausted = auto()
    source_unavailable = auto()
    unknown = auto()


class CaptureError(RuntimeError):
    """Base class for all capture‑service errors.

    Sub‑classes must define a ``category`` attribute of type
    :class:`CaptureErrorCategory` so that the Flask layer can translate it
    into an appropriate HTTP status code.
    """

    category: CaptureErrorCategory = CaptureErrorCategory.unknown

    def __init__(self, message: str = "Capture error"):
        super().__init__(message)


class CaptureMissingDependencyError(CaptureError):
    category = CaptureErrorCategory.missing_dependency


class CapturePermissionError(CaptureError):
    category = CaptureErrorCategory.permission_denied


class CaptureInvalidInterfaceError(CaptureError):
    category = CaptureErrorCategory.invalid_interface


class CaptureDisabledError(CaptureError):
    """Raised when configuration disables capture (CAPTURE_ENABLED=False)."""

    category = CaptureErrorCategory.capture_disabled


class CaptureAlreadyRunningError(CaptureError):
    category = CaptureErrorCategory.already_running


class CaptureNotRunningError(CaptureError):
    category = CaptureErrorCategory.not_running


class CaptureSourceInitializationError(CaptureError):
    category = CaptureErrorCategory.source_initialization_failed


class CaptureUnexpectedError(CaptureError):
    category = CaptureErrorCategory.capture_failed


class CaptureQueueOverflowError(CaptureError):
    category = CaptureErrorCategory.queue_overflow


class CaptureLimitReachedError(CaptureError):
    """Base for limit‑reached errors; concrete subclasses add details."""

    category = CaptureErrorCategory.unknown


class CapturePacketLimitReachedError(CaptureLimitReachedError):
    category = CaptureErrorCategory.packet_limit_reached
    stop_reason = "packet_limit_reached"


class CaptureDurationLimitReachedError(CaptureLimitReachedError):
    category = CaptureErrorCategory.duration_limit_reached
    stop_reason = "duration_limit_reached"



class CaptureStopTimeoutError(CaptureError):
    category = CaptureErrorCategory.stop_timeout


class CaptureResourceExhaustedError(CaptureError):
    category = CaptureErrorCategory.resource_exhausted


class CaptureSourceUnavailableError(CaptureError):
    category = CaptureErrorCategory.source_unavailable
