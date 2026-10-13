"""Safe dashboard adapter for explicit live metadata-flow evaluation."""


def _iso(value):
    return value.isoformat().replace("+00:00", "Z") if value else None


def _safe_record(record):
    if record is None:
        return None
    return {
        "evaluation_id": record.evaluation_id,
        "flow_id": record.flow_id,
        "flow_schema_version": record.flow_schema_version,
        "evaluated_at": _iso(record.evaluated_at),
        "feature_compatible": record.feature_compatible,
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
        "source_category": record.source_category,
        "safe_error_category": record.safe_error_category,
        "evaluation_schema_version": record.evaluation_schema_version,
        "alert_persisted": record.alert_persisted,
        "persisted_alert_id": record.persisted_alert_id,
        "alert_created_at": _iso(record.alert_created_at),
        "notification_sent": record.notification_sent,
        "blocking_executed": record.blocking_executed,
    }


class DashboardLiveFlowEvaluationService:
    def __init__(self, evaluation_service, state_service, aggregation_service,
                 alert_creation_service=None):
        self._evaluation = evaluation_service
        self._state = state_service
        self._aggregation = aggregation_service
        self._alert_creation = alert_creation_service

    def evaluate(self):
        return self._evaluation.evaluate()

    def status(self):
        state = self._state.snapshot()
        all_records = self._state.snapshot(recent_limit=10_000).recent_records
        completed = self._aggregation.status_snapshot().completed_flow_count
        eligible_count = sum(
            1 for record in all_records
            if self._alert_creation and self._alert_creation.eligible(record)
        )
        created = tuple(record for record in all_records if record.alert_persisted)
        latest_link = created[-1] if created else None
        return {
            "evaluation_request_count": state.evaluation_request_count,
            "flows_considered_count": state.flows_considered_count,
            "flows_skipped_already_evaluated_count": state.flows_skipped_already_evaluated_count,
            "evaluation_incompatible_flow_count": state.incompatible_flow_count,
            "successful_live_inference_count": state.successful_inference_count,
            "failed_live_inference_count": state.failed_inference_count,
            "successful_live_policy_count": state.successful_policy_count,
            "failed_live_policy_count": state.failed_policy_count,
            "live_recommendation_count": state.recommendation_count,
            "eligible_live_alert_recommendation_count": eligible_count,
            "manually_created_live_alert_count": len(created),
            "latest_live_alert_linkage": ({
                "evaluation_id": latest_link.evaluation_id,
                "alert_id": latest_link.persisted_alert_id,
                "created_at": _iso(latest_link.alert_created_at),
            } if latest_link else None),
            "retained_evaluation_count": state.retained_evaluation_count,
            "evaluation_eviction_count": state.evaluation_eviction_count,
            "eligible_flow_count": max(
                0, completed - state.successfully_evaluated_flow_count
            ),
            "latest_live_evaluation": _safe_record(state.latest_record),
            "recent_live_evaluations": tuple(
                _safe_record(record) for record in state.recent_records
            ),
        }

    def presentation(self, session_csrf):
        status = self.status()
        records = []
        for item in status["recent_live_evaluations"]:
            presented = dict(item)
            presented["recommendation_token"] = (
                self._alert_creation.generate_token(item["evaluation_id"], session_csrf)
                if self._alert_creation else None
            )
            records.append(presented)
        status["recent_live_evaluations"] = tuple(records)
        return status

    def create_alert(self, evaluation_id, token, session_csrf):
        if self._alert_creation is None:
            raise RuntimeError("Live-flow alert creation is unavailable")
        return self._alert_creation.create_alert(evaluation_id, token, session_csrf)
