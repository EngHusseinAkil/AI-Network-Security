"""
Decision Policy logic for Alerts.
Evaluates threat predictions and outputs alert recommendations.
Pure functions and dataclasses only. No side effects.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from alerts.constants import AlertType, AlertSeverity, PolicyReasonCode
from alerts.exceptions import PolicyConfigurationError
from alerts.models import _check_aware_utc

@dataclass(frozen=True)
class DecisionInput:
    """Safe input contract for the decision policy."""
    predicted_canonical_label: str
    confidence_score: float
    risk_score: float
    model_version: str
    schema_version: str
    source_category: str
    occurrence_count: int
    observation_window_seconds: int
    current_monitoring_state: str
    pseudonymous_source_key: str = "global"

    def __post_init__(self):
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ValueError("confidence_score must be between 0.0 and 1.0")
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError("risk_score must be between 0.0 and 1.0")

@dataclass(frozen=True)
class DecisionOutput:
    """Structured output recommendation from the policy."""
    should_create_alert: bool
    proposed_type: Optional[AlertType]
    proposed_severity: Optional[AlertSeverity]
    reason_code: PolicyReasonCode
    cooldown_key: Optional[str]
    suppression_status: str
    policy_version: str
    explanation: str

@dataclass(frozen=True)
class ThresholdConfig:
    """Configuration for policy evaluation thresholds."""
    min_risk: float = 0.6
    min_confidence: float = 0.7
    elevated_risk: float = 0.8
    critical_risk: float = 0.95
    repeated_event_count: int = 5
    cooldown_duration_seconds: int = 300

    def __post_init__(self):
        # Validate ordering and bounds
        if not (0.0 <= self.min_risk <= self.elevated_risk <= self.critical_risk <= 1.0):
            raise PolicyConfigurationError("Risk thresholds must be strictly ordered: min <= elevated <= critical")
        if not (0.0 <= self.min_confidence <= 1.0):
            raise PolicyConfigurationError("Confidence threshold must be between 0.0 and 1.0")
        if self.repeated_event_count < 1:
            raise PolicyConfigurationError("repeated_event_count must be >= 1")
        if self.cooldown_duration_seconds < 0:
            raise PolicyConfigurationError("cooldown_duration_seconds must be non-negative")


class AlertPolicy:
    """Pure evaluator for alert decisions."""

    VERSION = "1.0.0"

    def __init__(self, config: ThresholdConfig = None):
        self.config = config or ThresholdConfig()

    def evaluate(self, decision_input: DecisionInput) -> DecisionOutput:
        """
        Evaluates the input and returns a recommendation without side effects.
        """
        label = decision_input.predicted_canonical_label
        risk = decision_input.risk_score
        conf = decision_input.confidence_score

        # 1. Benign Policy
        if label == "benign":
            # Even if risk score is high (contradiction from model), we enforce benign = no alert.
            return DecisionOutput(
                should_create_alert=False,
                proposed_type=None,
                proposed_severity=None,
                reason_code=PolicyReasonCode.BENIGN_PREDICTION,
                cooldown_key=None,
                suppression_status="suppressed_benign",
                policy_version=self.VERSION,
                explanation="Prediction is benign; no alert required."
            )

        # 2. Unknown Label Policy
        if label in ("unknown", "unclassified", "suspicious_unknown"):
            if risk >= self.config.min_risk and conf >= self.config.min_confidence:
                severity = AlertSeverity.MEDIUM if risk >= self.config.elevated_risk else AlertSeverity.LOW
                return DecisionOutput(
                    should_create_alert=True,
                    proposed_type=AlertType.SUSPICIOUS_UNKNOWN,
                    proposed_severity=severity,
                    reason_code=PolicyReasonCode.UNKNOWN_UNCERTAINTY,
                    cooldown_key=self._generate_cooldown_key(AlertType.SUSPICIOUS_UNKNOWN, decision_input),
                    suppression_status="none",
                    policy_version=self.VERSION,
                    explanation="Suspicious unknown activity met risk thresholds."
                )
            else:
                return DecisionOutput(
                    should_create_alert=False,
                    proposed_type=None,
                    proposed_severity=None,
                    reason_code=PolicyReasonCode.BELOW_THRESHOLD,
                    cooldown_key=None,
                    suppression_status="suppressed_below_threshold",
                    policy_version=self.VERSION,
                    explanation="Unknown activity did not meet minimum risk/confidence thresholds."
                )

        # 3. Known Threats Policy
        if risk < self.config.min_risk or conf < self.config.min_confidence:
            return DecisionOutput(
                should_create_alert=False,
                proposed_type=None,
                proposed_severity=None,
                reason_code=PolicyReasonCode.BELOW_THRESHOLD,
                cooldown_key=None,
                suppression_status="suppressed_below_threshold",
                policy_version=self.VERSION,
                explanation="Threat prediction did not meet minimum risk/confidence thresholds."
            )

        # Determine Alert Type heuristically (this would map canonical labels to AlertTypes)
        try:
            alert_type = AlertType(f"suspected_{label}")
        except ValueError:
            alert_type = AlertType.SUSPICIOUS_UNKNOWN

        # Determine Severity based on context (not just risk score)
        severity = AlertSeverity.LOW
        reason = PolicyReasonCode.RISK_THRESHOLD_MET

        if decision_input.occurrence_count >= self.config.repeated_event_count:
            severity = AlertSeverity.HIGH
            reason = PolicyReasonCode.REPEATED_ACTIVITY
        elif risk >= self.config.critical_risk and alert_type in (AlertType.SUSPECTED_DDOS, AlertType.SUSPECTED_MALWARE):
            severity = AlertSeverity.CRITICAL
        elif risk >= self.config.elevated_risk:
            severity = AlertSeverity.MEDIUM

        return DecisionOutput(
            should_create_alert=True,
            proposed_type=alert_type,
            proposed_severity=severity,
            reason_code=reason,
            cooldown_key=self._generate_cooldown_key(alert_type, decision_input),
            suppression_status="none",
            policy_version=self.VERSION,
            explanation=f"Threat detected matching criteria for {severity.value} alert."
        )

    def _generate_cooldown_key(self, alert_type: AlertType, decision_input: DecisionInput) -> str:
        """Deterministic cooldown key using only safe fields."""
        # Note: Do not use raw IP/MAC here. We use the pseudonymous key.
        return f"cd:{alert_type.value}:{decision_input.pseudonymous_source_key}"


def is_in_cooldown(last_alert_timestamp: Optional[datetime], current_timestamp: datetime, cooldown_duration_seconds: int) -> bool:
    """
    Pure function to evaluate if an alert should be suppressed due to cooldown.
    Requires timezone-aware UTC timestamps.
    """
    _check_aware_utc(current_timestamp, "current_timestamp")

    if last_alert_timestamp is None:
        return False

    _check_aware_utc(last_alert_timestamp, "last_alert_timestamp")

    if current_timestamp < last_alert_timestamp:
        # Invalid state: current time before last alert. Treat as NOT in cooldown to be safe (or fail closed).
        # We fail open (False) to avoid permanent suppression if clocks skew backwards.
        return False

    delta = current_timestamp - last_alert_timestamp
    return delta.total_seconds() < cooldown_duration_seconds
