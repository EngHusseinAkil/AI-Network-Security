"""
Monitoring Simulation Service.

Provides a deterministic simulation path for testing the future monitoring pipeline
by connecting a simulated flow event to the inference and alert-policy boundaries.
"""

import logging
from typing import Dict, Any
import uuid

from utils.time_utils import get_current_utc_time
from alerts.policy import DecisionInput
from backend.services.monitoring_service import MonitoringStateService
from backend.services.inference_service import InferenceService
from backend.schemas.monitoring import SimulationHistoryRecord

logger = logging.getLogger(__name__)

class MonitoringSimulationService:
    def __init__(
        self,
        inference_service: InferenceService,
        alert_policy,
        monitoring_state_service: MonitoringStateService
    ):
        self._inference = inference_service
        self._policy = alert_policy
        self._monitoring_state = monitoring_state_service

    def simulate_flow(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Executes a deterministic simulated monitoring cycle.
        """
        # 1-3. acquire a simulation execution guard; mark the cycle as running; release lock
        # Preserve the validated submission across the POST/redirect render.
        submitted_features = dict(features)
        self._monitoring_state.update_simulation_start()

        started_at = get_current_utc_time()
        inference_status = "success"
        policy_status = "success"
        predicted_label = None
        confidence = None
        risk_score = None
        model_version = None
        schema_version = None

        alert_recommended = False
        proposed_type = None
        proposed_severity = None
        reason_code = None
        policy_version = None
        safe_error = None

        try:
            # 4. perform inference (lock is NOT held)
            try:
                inference_result = self._inference.predict_flow(features)
                predicted_label = inference_result.get("predicted_canonical_label")
                confidence = inference_result.get("confidence_score")
                risk_score = inference_result.get("risk_score")
                model_version = inference_result.get("model_version")
                schema_version = inference_result.get("schema_version")
            except Exception as e:
                logger.exception("Inference failed during simulation.")
                inference_status = "error"
                safe_error = "inference_unavailable"
                completed_at = get_current_utc_time()
                duration_ms = (completed_at - started_at).total_seconds() * 1000.0
                cycle_id = str(uuid.uuid4())
                history_record = SimulationHistoryRecord(
                    cycle_id=cycle_id,
                    state="error",
                    source_category="simulated_monitoring",
                    started_at=started_at.isoformat(),
                    completed_at=completed_at.isoformat(),
                    duration_ms=duration_ms,
                    inference_status=inference_status,
                    safe_error_category=safe_error
                )
                self._monitoring_state.update_simulation_inference_failure(safe_error, history_record)
                raise

            # 5. perform policy evaluation
            try:
                decision_input = DecisionInput(
                    predicted_canonical_label=predicted_label,
                    confidence_score=confidence,
                    risk_score=risk_score,
                    model_version=model_version,
                    schema_version=schema_version,
                    source_category="simulated_monitoring",
                    occurrence_count=1,
                    observation_window_seconds=1,
                    current_monitoring_state="running",
                    pseudonymous_source_key="simulated_device"
                )
                policy_output = self._policy.evaluate(decision_input)
                alert_recommended = policy_output.should_create_alert
                proposed_type = policy_output.proposed_type.value if policy_output.proposed_type else None
                proposed_severity = policy_output.proposed_severity.value if policy_output.proposed_severity else None
                reason_code = policy_output.reason_code.value
                policy_version = policy_output.policy_version

            except Exception as e:
                logger.exception("Policy evaluation failed during simulation.")
                policy_status = "error"
                safe_error = "policy_unavailable"
                completed_at = get_current_utc_time()
                duration_ms = (completed_at - started_at).total_seconds() * 1000.0
                cycle_id = str(uuid.uuid4())
                history_record = SimulationHistoryRecord(
                    cycle_id=cycle_id,
                    state="error",
                    source_category="simulated_monitoring",
                    started_at=started_at.isoformat(),
                    completed_at=completed_at.isoformat(),
                    duration_ms=duration_ms,
                    inference_status=inference_status,
                    predicted_canonical_label=predicted_label,
                    confidence_score=confidence,
                    risk_score=risk_score,
                    model_version=model_version,
                    policy_status=policy_status,
                    safe_error_category=safe_error
                )
                self._monitoring_state.update_simulation_error(safe_error, history_record)
                raise

            # 6. construct the immutable result
            completed_at = get_current_utc_time()
            duration_ms = (completed_at - started_at).total_seconds() * 1000.0

            cycle_id = str(uuid.uuid4())

            result = {
                "simulation_cycle_id": cycle_id,
                "state": "simulation_complete",
                "started_timestamp": started_at.isoformat(),
                "completed_timestamp": completed_at.isoformat(),
                "duration": duration_ms,
                "inference_status": inference_status,
                "features": submitted_features,
                "predicted_canonical_label": predicted_label,
                "confidence": confidence,
                "risk_score": risk_score,
                "model_version": model_version,
                "policy_status": policy_status,
                "alert_recommended": alert_recommended,
                "proposed_alert_type": proposed_type,
                "proposed_severity": proposed_severity,
                "reason_code": reason_code,
                "policy_version": policy_version,
                "safe_error_category": None,
                "alert_persisted": False,
                "notification_sent": False,
                "blocking_executed": False
            }

            # 7 & 8. update counters and latest result atomically
            history_record = SimulationHistoryRecord(
                cycle_id=cycle_id,
                state="simulation_complete",
                source_category="simulated_monitoring",
                started_at=started_at.isoformat(),
                completed_at=completed_at.isoformat(),
                duration_ms=duration_ms,
                inference_status=inference_status,
                predicted_canonical_label=predicted_label,
                confidence_score=confidence,
                risk_score=risk_score,
                model_version=model_version,
                policy_status=policy_status,
                alert_recommended=alert_recommended,
                proposed_alert_type=proposed_type,
                proposed_severity=proposed_severity,
                reason_code=reason_code,
                policy_version=policy_version,
                safe_error_category=None
            )
            self._monitoring_state.update_simulation_success(result, started_at.isoformat(), alert_recommended, history_record)
            return result

        except Exception as e:
            if not safe_error:
                safe_error = "unexpected_simulation_error"
                completed_at = get_current_utc_time()
                duration_ms = (completed_at - started_at).total_seconds() * 1000.0
                cycle_id = str(uuid.uuid4())
                history_record = SimulationHistoryRecord(
                    cycle_id=cycle_id,
                    state="error",
                    source_category="simulated_monitoring",
                    started_at=started_at.isoformat(),
                    completed_at=completed_at.isoformat(),
                    duration_ms=duration_ms,
                    inference_status=inference_status,
                    predicted_canonical_label=predicted_label,
                    confidence_score=confidence,
                    risk_score=risk_score,
                    model_version=model_version,
                    policy_status=policy_status,
                    alert_recommended=alert_recommended,
                    proposed_alert_type=proposed_type,
                    proposed_severity=proposed_severity,
                    reason_code=reason_code,
                    policy_version=policy_version,
                    safe_error_category=safe_error
                )
                self._monitoring_state.update_simulation_error(safe_error, history_record)

            completed_at = get_current_utc_time()
            duration_ms = (completed_at - started_at).total_seconds() * 1000.0
            cycle_id = str(uuid.uuid4())

            result = {
                "simulation_cycle_id": cycle_id,
                "state": "error",
                "started_timestamp": started_at.isoformat(),
                "completed_timestamp": completed_at.isoformat(),
                "duration": duration_ms,
                "inference_status": inference_status,
                "features": submitted_features,
                "predicted_canonical_label": predicted_label,
                "confidence": confidence,
                "risk_score": risk_score,
                "model_version": model_version,
                "policy_status": policy_status,
                "alert_recommended": False,
                "proposed_alert_type": None,
                "proposed_severity": None,
                "reason_code": None,
                "policy_version": policy_version,
                "safe_error_category": safe_error,
                "alert_persisted": False,
                "notification_sent": False,
                "blocking_executed": False
            }
            return result

        finally:
            self._monitoring_state.clear_running_state()
