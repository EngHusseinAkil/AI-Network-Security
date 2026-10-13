import csv
import io
import math
from typing import Dict, Any, List
from utils.time_utils import get_current_utc_time
from backend.services.monitoring_service import MonitoringStateService
from backend.schemas.monitoring import SimulationHistoryRecord

class SimulationEvaluationReportService:
    def __init__(self, monitoring_state_service: MonitoringStateService):
        self._monitoring_state = monitoring_state_service

    def _neutralize_csv_value(self, value: Any) -> str:
        """Prevent spreadsheet formula injection."""
        if value is None:
            return ""
        
        # Keep numeric values as-is (except string negatives)
        if isinstance(value, (int, float)):
            return str(value)
            
        s = str(value)
        if s.startswith(("=", "+", "-", "@", "\t", "\r")):
            # Important: do not convert legitimate numeric negative values into text unnecessarily
            # Check if it's a valid negative number before escaping
            if s.startswith("-"):
                try:
                    float(s)
                    return s # It's a valid negative number, keep as-is
                except ValueError:
                    pass # Not a number, escape it
            return f"'{s}"
        return s

    def get_summary_metrics(self, history_snapshot: List[SimulationHistoryRecord]) -> Dict[str, Any]:
        """Compute summary metrics from a single immutable history snapshot."""
        total_retained = len(history_snapshot)
        
        successful_inference = 0
        failed_inference = 0
        successful_policy = 0
        failed_policy = 0
        recommendation_count = 0
        
        predicted_label_counts = {}
        proposed_severity_counts = {}
        
        total_duration = 0.0
        valid_duration_count = 0
        
        for record in history_snapshot:
            if record.inference_status == "success":
                successful_inference += 1
            elif record.inference_status == "error":
                failed_inference += 1
                
            if record.policy_status == "success":
                successful_policy += 1
            elif record.policy_status == "error":
                failed_policy += 1
                
            if record.alert_recommended:
                recommendation_count += 1
                
            if record.predicted_canonical_label:
                label = record.predicted_canonical_label
                predicted_label_counts[label] = predicted_label_counts.get(label, 0) + 1
                
            if record.proposed_severity:
                sev = record.proposed_severity
                proposed_severity_counts[sev] = proposed_severity_counts.get(sev, 0) + 1
                
            if record.duration_ms is not None and math.isfinite(record.duration_ms) and record.duration_ms >= 0:
                total_duration += record.duration_ms
                valid_duration_count += 1
                
        # recommendation rate denominator: successful_policy evaluations
        recommendation_rate = 0.0
        if successful_policy > 0:
            recommendation_rate = recommendation_count / successful_policy
            
        avg_duration = 0.0
        if valid_duration_count > 0:
            avg_duration = total_duration / valid_duration_count
            
        oldest_at = None
        newest_at = None
        if history_snapshot:
            # history_snapshot is assumed to be chronological (oldest to newest) when passed here
            # or we can just sort by started_at if not sure.
            # But the contract is that the passed snapshot is chronological.
            # Let's ensure by looking at first and last.
            oldest_at = history_snapshot[0].started_at
            newest_at = history_snapshot[-1].started_at

        return {
            "total_retained_cycles": total_retained,
            "successful_inference_cycles": successful_inference,
            "failed_inference_cycles": failed_inference,
            "successful_policy_evaluations": successful_policy,
            "failed_policy_evaluations": failed_policy,
            "recommendation_count": recommendation_count,
            "recommendation_rate": recommendation_rate,
            "predicted_label_counts": predicted_label_counts,
            "proposed_severity_counts": proposed_severity_counts,
            "average_cycle_duration_ms": avg_duration,
            "oldest_retained_at": oldest_at,
            "newest_retained_at": newest_at
        }

    def generate_json_report(self) -> Dict[str, Any]:
        """Generate a complete JSON report DTO."""
        history = self._monitoring_state._get_history_snapshot_chronological()
        metrics = self.get_summary_metrics(history)
        
        cycles = []
        for record in history:
            cycles.append({
                "cycle_id": record.cycle_id,
                "state": record.state,
                "source_category": record.source_category,
                "started_at": record.started_at,
                "completed_at": record.completed_at,
                "duration_ms": record.duration_ms,
                "simulated": record.simulated,
                "alert_persisted": record.alert_persisted,
                "notification_sent": record.notification_sent,
                "blocking_executed": record.blocking_executed,
                "inference_status": record.inference_status,
                "predicted_canonical_label": record.predicted_canonical_label,
                "confidence_score": record.confidence_score,
                "risk_score": record.risk_score,
                "model_version": record.model_version,
                "policy_status": record.policy_status,
                "alert_recommended": record.alert_recommended,
                "proposed_alert_type": record.proposed_alert_type,
                "proposed_severity": record.proposed_severity,
                "reason_code": record.reason_code,
                "policy_version": record.policy_version,
                "safe_error_category": record.safe_error_category
            })

        return {
            "report_schema_version": "simulation-report-v1",
            "generated_at_utc": get_current_utc_time().isoformat(),
            "simulation_only_disclaimer": "This is a simulated monitoring report. No actual live capture or alert persistence occurred.",
            "process_local_limitations": "History is process-local and lost upon restart. It isolates across multiple workers.",
            "side_effect_guarantees": "No automatic alert persistence, ThreatLog writes, notifications, or blocking occurred.",
            "configured_history_limit": self._monitoring_state.get_history_limit(),
            "retained_record_count": len(history),
            "summary_metrics": metrics,
            "cycles": cycles
        }

    def generate_csv_report(self) -> str:
        """Generate a complete CSV report as a string."""
        history = self._monitoring_state._get_history_snapshot_chronological()
        
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        
        headers = [
            "Cycle ID", "State", "Source Category", "Started At", "Completed At", 
            "Duration (ms)", "Inference Status", "Predicted Label", "Confidence", 
            "Risk", "Model Version", "Policy Status", "Alert Recommended", 
            "Proposed Type", "Proposed Severity", "Reason Code", "Policy Version", 
            "Error Category", "Simulated", "Alert Persisted", "Notification Sent", "Blocking Executed"
        ]
        writer.writerow(headers)
        
        for record in history:
            row = [
                self._neutralize_csv_value(record.cycle_id),
                self._neutralize_csv_value(record.state),
                self._neutralize_csv_value(record.source_category),
                self._neutralize_csv_value(record.started_at),
                self._neutralize_csv_value(record.completed_at),
                record.duration_ms, # Keep numeric
                self._neutralize_csv_value(record.inference_status),
                self._neutralize_csv_value(record.predicted_canonical_label),
                record.confidence_score, # Keep numeric
                record.risk_score, # Keep numeric
                self._neutralize_csv_value(record.model_version),
                self._neutralize_csv_value(record.policy_status),
                str(record.alert_recommended).lower(),
                self._neutralize_csv_value(record.proposed_alert_type),
                self._neutralize_csv_value(record.proposed_severity),
                self._neutralize_csv_value(record.reason_code),
                self._neutralize_csv_value(record.policy_version),
                self._neutralize_csv_value(record.safe_error_category),
                str(record.simulated).lower(),
                str(record.alert_persisted).lower(),
                str(record.notification_sent).lower(),
                str(record.blocking_executed).lower()
            ]
            writer.writerow(row)
            
        return output.getvalue()
