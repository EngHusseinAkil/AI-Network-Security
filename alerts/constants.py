"""
Constants and enumerations for the Alert Domain.
"""

from enum import Enum, unique

@unique
class AlertType(str, Enum):
    """Canonical alert types. These are separate from AI labels."""
    SUSPECTED_DDOS = "suspected_ddos"
    SUSPECTED_PORT_SCAN = "suspected_port_scan"
    SUSPECTED_BRUTE_FORCE = "suspected_brute_force"
    SUSPECTED_BOTNET = "suspected_botnet"
    SUSPECTED_MALWARE = "suspected_malware"
    SUSPICIOUS_UNKNOWN = "suspicious_unknown"
    MODEL_UNAVAILABLE = "model_unavailable"
    MONITORING_DEGRADED = "monitoring_degraded"
    SYSTEM_HEALTH_FAILURE = "system_health_failure"


@unique
class AlertSeverity(str, Enum):
    """Deterministic severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@unique
class AlertStatus(str, Enum):
    """Alert lifecycle statuses."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


@unique
class PolicyReasonCode(str, Enum):
    """Safe reason codes for policy explanations."""
    BELOW_THRESHOLD = "below_threshold"
    BENIGN_PREDICTION = "benign_prediction"
    RISK_THRESHOLD_MET = "risk_threshold_met"
    REPEATED_ACTIVITY = "repeated_activity"
    COOLDOWN_ACTIVE = "cooldown_active"
    UNKNOWN_UNCERTAINTY = "unknown_uncertainty"
    MONITORING_DEGRADED = "monitoring_degraded"

# Valid state transitions mapping from current status to allowed next statuses
VALID_TRANSITIONS = {
    AlertStatus.NEW: {AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED, AlertStatus.DISMISSED},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.RESOLVED, AlertStatus.DISMISSED},
    AlertStatus.RESOLVED: set(),
    AlertStatus.DISMISSED: set(),
}
