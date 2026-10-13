"""Explicit orchestration for retained metadata-flow evaluation.

This service performs no persistence or response actions. It is invoked only by
the explicit dashboard POST registered by the application boundary.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import math
import uuid

from alerts.policy import DecisionInput
from network.live_flow_evaluation_models import (
    LiveFlowEvaluationRecord, LiveFlowEvaluationRequestResult, SOURCE_CATEGORY,
)


class LiveFlowEvaluationService:
    def __init__(self, completed_flow_provider, feature_service, inference_service,
                 alert_policy, state_service, config, utc_clock=None, logger=None):
        self._flows = completed_flow_provider
        self._features = feature_service
        self._inference = inference_service
        self._policy = alert_policy
        self._state = state_service
        self._config = config
        self._utc = utc_clock or (lambda: datetime.now(timezone.utc))
        self._logger = logger

    def evaluate(self):
        self._state.begin_request()
        flows = self._flows.completed_snapshot()
        policy_version = str(self._policy.VERSION)
        try:
            model_version = str(self._inference.get_model_info().get("model_version") or "unknown")
        except Exception:
            model_version = "unavailable"
        considered = retained = skipped = 0
        for flow in flows[:self._config.max_flows_per_request]:
            considered += 1
            key = self.build_evaluation_key(
                flow.flow_id, flow.schema_version, model_version,
                policy_version, self._config.schema_version,
            )
            if not self._state.reserve(key):
                skipped += 1
                continue
            try:
                record = self._evaluate_one(flow, key, model_version, policy_version)
                if self._state.retain(record):
                    retained += 1
            except Exception:
                self._state.release(key)
                if self._logger:
                    self._logger.warning("Live metadata-flow evaluation failed safely")
        return LiveFlowEvaluationRequestResult(considered, retained, skipped)

    @staticmethod
    def build_evaluation_key(flow_id, flow_schema, model_version,
                             policy_version, evaluation_schema):
        material = "|".join((
            flow_id, flow_schema, model_version, policy_version, evaluation_schema
        ))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _evaluate_one(self, flow, key, model_version, policy_version):
        extracted = self._features.extract(flow)
        if not extracted.compatible:
            return self._record(
                flow, key, model_version, policy_version,
                feature_compatible=False, inference_status="not_run",
                policy_status="not_run",
                safe_error_category=extracted.incompatibility_reason or "incompatible_flow",
            )

        feature_dict = asdict(extracted.vector)
        try:
            prediction = self._inference.predict_flow(feature_dict)
            predicted_label = prediction.get("predicted_canonical_label")
            confidence = prediction.get("confidence_score")
            risk = prediction.get("risk_score")
            result_model_version = str(prediction.get("model_version") or model_version)
            self._bounded_score(confidence, "confidence")
            self._bounded_score(risk, "risk")
        except Exception:
            return self._record(
                flow, key, model_version, policy_version,
                feature_compatible=True, inference_status="failed",
                policy_status="not_run", safe_error_category="inference_unavailable",
            )

        try:
            decision = DecisionInput(
                predicted_canonical_label=predicted_label,
                confidence_score=float(confidence),
                risk_score=float(risk),
                model_version=result_model_version,
                schema_version=flow.schema_version,
                source_category=SOURCE_CATEGORY,
                occurrence_count=1,
                observation_window_seconds=max(1, math.ceil(flow.duration_seconds)),
                current_monitoring_state="metadata_flow_evaluation",
                pseudonymous_source_key=flow.flow_id,
            )
            output = self._policy.evaluate(decision)
        except Exception:
            return self._record(
                flow, key, result_model_version, policy_version,
                feature_compatible=True, inference_status="success",
                predicted_canonical_label=predicted_label,
                confidence_score=float(confidence), risk_score=float(risk),
                policy_status="failed", safe_error_category="policy_unavailable",
            )

        return self._record(
            flow, key, result_model_version, str(output.policy_version),
            feature_compatible=True, inference_status="success",
            predicted_canonical_label=predicted_label,
            confidence_score=float(confidence), risk_score=float(risk),
            policy_status="success",
            alert_recommended=bool(output.should_create_alert),
            proposed_alert_type=self._enum_value(output.proposed_type),
            proposed_severity=self._enum_value(output.proposed_severity),
            reason_code=self._enum_value(output.reason_code),
        )

    def _record(self, flow, key, model_version, policy_version, **values):
        defaults = {
            "feature_compatible": False,
            "inference_status": "not_run",
            "predicted_canonical_label": None,
            "confidence_score": None,
            "risk_score": None,
            "policy_status": "not_run",
            "alert_recommended": False,
            "proposed_alert_type": None,
            "proposed_severity": None,
            "reason_code": None,
            "safe_error_category": None,
        }
        defaults.update(values)
        return LiveFlowEvaluationRecord(
            evaluation_id=str(uuid.uuid4()),
            evaluation_key=key,
            flow_id=flow.flow_id,
            flow_schema_version=flow.schema_version,
            evaluated_at=self._utc(),
            model_version=model_version,
            policy_version=policy_version,
            source_category=SOURCE_CATEGORY,
            evaluation_schema_version=self._config.schema_version,
            **defaults,
        )

    @staticmethod
    def _enum_value(value):
        return value.value if value is not None and hasattr(value, "value") else value

    @staticmethod
    def _bounded_score(value, name):
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value) or not 0 <= value <= 1):
            raise ValueError(f"{name} score is invalid")
