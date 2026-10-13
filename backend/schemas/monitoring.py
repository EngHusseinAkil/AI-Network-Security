from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, slots=True)
class SimulationHistoryRecord:
    cycle_id: str
    state: str
    source_category: str
    started_at: str
    completed_at: str
    duration_ms: float
    simulated: bool = True
    alert_persisted: bool = False
    notification_sent: bool = False
    blocking_executed: bool = False

    # Inference Data
    inference_status: str = "unavailable"
    predicted_canonical_label: Optional[str] = None
    confidence_score: Optional[float] = None
    risk_score: Optional[float] = None
    model_version: Optional[str] = None

    # Policy Data
    policy_status: str = "unavailable"
    alert_recommended: bool = False
    proposed_alert_type: Optional[str] = None
    proposed_severity: Optional[str] = None
    reason_code: Optional[str] = None
    policy_version: Optional[str] = None

    # Error Details
    safe_error_category: Optional[str] = None
