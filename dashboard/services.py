"""
Dashboard service boundaries.
"""
import logging

logger = logging.getLogger(__name__)

class DashboardHealthService:
    """Service boundary for dashboard health views."""

    def __init__(self, system_health_svc, ai_health_svc, backend_health_svc):
        self.system_health_svc = system_health_svc
        self.ai_health_service = ai_health_svc
        self.backend_health_svc = backend_health_svc

    def get_system_health(self) -> dict:
        """Safely fetch system health."""
        try:
            return self.system_health_svc.get_health_summary()
        except Exception as e:
            logger.error("Dashboard failed to fetch system health: %s", str(e))
            return self._build_fallback("System Health")

    def get_ai_health(self) -> dict:
        """Safely fetch AI health."""
        try:
            return self.ai_health_service.get_health_summary()
        except Exception as e:
            logger.error("Dashboard failed to fetch AI health: %s", str(e))
            return self._build_fallback("AI Health")

    def get_backend_health(self) -> dict:
        """Safely fetch backend health."""
        try:
            return self.backend_health_svc.get_health_summary()
        except Exception as e:
            logger.error("Dashboard failed to fetch backend health: %s", str(e))
            return self._build_fallback("Backend Health")

    def _build_fallback(self, component: str) -> dict:
        return {
            "overall_status": "failed",
            "message": f"{component} service is currently unavailable.",
            "checks": [],
            "error_category": "service_unavailable"
        }

class DashboardOverviewService:
    """Service boundary for dashboard overview. Not implemented yet."""
    pass

class DashboardModelService:
    """Service boundary for dashboard models."""
    def __init__(self, model_service):
        self.model_service = model_service

    def get_model_overview(self) -> dict:
        """Safely fetch model overview without exposing internals."""
        try:
            if hasattr(self.model_service, "get_models"):
                listing = self.model_service.get_models()
                models = listing.get("models", [])
                active_result = self.model_service.get_active_model()
                active = (
                    active_result.get("model")
                    if active_result.get("active")
                    else None
                )
                if active:
                    active["expected_feature_count"] = active.get("feature_count")
                    registered_active = next(
                        (
                            item for item in models
                            if item.get("model_version")
                            == active.get("model_version")
                        ),
                        {},
                    )
                    active["testing_only_fallback"] = registered_active.get(
                        "is_testing_fallback_split", False
                    )
                for model in models:
                    model["testing_only_fallback"] = model.get(
                        "is_testing_fallback_split", False
                    )
            else:
                models = self.model_service.get_available_models()
                active = self.model_service.get_active_model_metadata()

            return {
                "total_models": len(models),
                "active_model": active if active else None,
                "models": models,
                "error": None
            }
        except Exception as e:
            logger.error("Dashboard failed to fetch model info: %s", str(e))
            return {"total_models": 0, "active_model": None, "models": [], "error": "Model registry unavailable"}

class DashboardAlertEvaluationService:
    """Service boundary for evaluating alert policies on manual inference results."""

    def __init__(self, policy):
        self.policy = policy

    def evaluate_single_inference(self, inference_result: dict, pseudonymous_source_key: str = "manual_inference") -> dict:
        """
        Maps a successful inference result into a policy decision input, evaluates it,
        and returns a safe recommendation view model.
        """
        import logging
        logger = logging.getLogger(__name__)

        try:
            from alerts.policy import DecisionInput

            # Map inference result to DecisionInput
            decision_input = DecisionInput(
                predicted_canonical_label=inference_result.get("predicted_canonical_label", "unknown"),
                confidence_score=inference_result.get("confidence_score", 0.0),
                risk_score=inference_result.get("risk_score", 0.0),
                model_version=inference_result.get("model_version", "unknown"),
                schema_version=inference_result.get("schema_version", "unknown"),
                source_category="manual_dashboard_inference",
                occurrence_count=1,
                observation_window_seconds=1,
                current_monitoring_state="disabled",
                pseudonymous_source_key=pseudonymous_source_key
            )

            # Evaluate policy
            output = self.policy.evaluate(decision_input)

            logger.info(
                "Policy evaluated for manual_dashboard_inference. Label: %s, Recommended: %s, Reason: %s",
                decision_input.predicted_canonical_label,
                output.should_create_alert,
                output.reason_code.value
            )

            # Map to view model
            return {
                "available": True,
                "should_create_alert": output.should_create_alert,
                "proposed_type": output.proposed_type.value if output.proposed_type else "None",
                "proposed_severity": output.proposed_severity.value if output.proposed_severity else "None",
                "reason_code": output.reason_code.value,
                "policy_version": output.policy_version,
                "suppression_status": output.suppression_status,
                "cooldown_status": "not_evaluated",  # Explicitly deferring cooldown history
                "explanation": output.explanation,
                "disclaimer": "This is a policy recommendation only. No alert has been created, no notification has been sent, and no traffic has been blocked. Model predictions are probabilistic and thresholds require operational tuning.",
                "error": None
            }

        except Exception as e:
            logger.exception("Policy evaluation failed safely: %s", str(e))
            return {
                "available": False,
                "error": "Policy evaluation unavailable due to internal error."
            }

    def evaluate_batch_inference(self, batch_meta: dict) -> dict:
        """Defer batch policy evaluation."""
        return {
            "available": False,
            "error": "Alert-policy evaluation is not available for batch inference in this milestone."
        }

class DashboardAlertCreationService:
    """Service boundary for creating alerts from recommendation tokens."""

    def __init__(self, persistence_service):
        self.persistence_service = persistence_service
        self.salt = "alert-recommendation"

    def _get_serializer(self):
        from flask import current_app
        from itsdangerous import URLSafeTimedSerializer
        return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=self.salt)

    def generate_recommendation_token(self, recommendation: dict, inference_result: dict, session_csrf: str) -> str:
        import hashlib
        import secrets
        import time

        if not recommendation.get("should_create_alert"):
            return None

        session_hash = hashlib.sha256(session_csrf.encode()).hexdigest()

        claims = {
            "predicted_canonical_label": inference_result.get("predicted_canonical_label"),
            "confidence_score": inference_result.get("confidence_score", 0.0),
            "risk_score": inference_result.get("risk_score", 0.0),
            "model_version": inference_result.get("model_version"),
            "schema_version": inference_result.get("schema_version"),
            "proposed_alert_type": recommendation.get("proposed_type"),
            "proposed_severity": recommendation.get("proposed_severity"),
            "reason_code": recommendation.get("reason_code"),
            "policy_version": recommendation.get("policy_version"),
            "source_category": "manual_dashboard_inference",
            "occurrence_count": 1,
            "session_hash": session_hash,
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time()),
            "purpose": "create_alert"
        }

        return self._get_serializer().dumps(claims)

    def create_alert_from_token(self, token: str, session_csrf: str) -> str:
        """
        Validates token, handles replays/duplicates, constructs domain alert,
        persists and returns the public_alert_id.
        """
        import hashlib
        from itsdangerous import SignatureExpired, BadSignature
        from utils.exceptions import ApplicationError, ConflictError
        from alerts.models import Alert as DomainAlert
        from alerts.constants import AlertType, AlertSeverity, AlertStatus
        from utils.time_utils import get_current_utc_time
        import uuid
        import logging

        logger = logging.getLogger(__name__)

        from utils.signed_tokens import is_canonical_signed_token
        if not is_canonical_signed_token(token):
            raise ApplicationError("The recommendation token is invalid or corrupted.")
        try:
            # 300 seconds (5 minutes) strict expiration
            claims = self._get_serializer().loads(token, max_age=300)
        except SignatureExpired:
            raise ApplicationError("The recommendation token has expired.")
        except BadSignature:
            raise ApplicationError("The recommendation token is invalid or corrupted.")

        if claims.get("purpose") != "create_alert":
            raise ApplicationError("Invalid token purpose.")

        # Verify session binding using constant-time comparison to prevent timing attacks.
        # The session hash is a SHA-256 digest of the CSRF token embedded in the signed token.
        # This is not HMAC — it is a plain SHA-256 digest used for binding, protected by the
        # itsdangerous signature. Do not log this value.
        expected_session_hash = hashlib.sha256(session_csrf.encode()).hexdigest()
        import secrets as _secrets
        if not _secrets.compare_digest(claims.get("session_hash", ""), expected_session_hash):
            raise ApplicationError("Token session binding failed. Cross-session request rejected.")

        # Replay protection / Deduplication
        nonce = claims.get("nonce")
        if not nonce:
            raise ApplicationError("Malformed token: missing nonce.")

        deduplication_key = hashlib.sha256(f"manual_dashboard_{nonce}".encode()).hexdigest()

        duplicate = self.persistence_service.find_by_deduplication_key(deduplication_key)
        if duplicate:
            raise ConflictError("Duplicate alert", details={"duplicate_id": duplicate.get("public_alert_id")})

        # Domain Alert Construction
        public_alert_id = str(uuid.uuid4())

        try:
            alert_type = AlertType(claims.get("proposed_alert_type"))
            severity = AlertSeverity(claims.get("proposed_severity"))
        except ValueError:
            raise ApplicationError("Invalid alert type or severity in recommendation token.")

        title = f"{alert_type.value.replace('_', ' ').title()} Detected"
        description = "Alert explicitly created from manual dashboard inference policy recommendation."

        domain_alert = DomainAlert(
            alert_id=public_alert_id,
            type=alert_type,
            severity=severity,
            status=AlertStatus.NEW,
            title=title,
            description=description,
            source_category=claims.get("source_category"),
            predicted_canonical_label=claims.get("predicted_canonical_label"),
            confidence_score=claims.get("confidence_score"),
            risk_score=claims.get("risk_score"),
            model_version=claims.get("model_version"),
            schema_version=claims.get("schema_version"),
            created_at=get_current_utc_time(),
            deduplication_key=deduplication_key,
            safe_metadata={"nonce_digest": hashlib.sha256(nonce.encode()).hexdigest()}
        )

        self.persistence_service.store_alert(
            domain_alert,
            policy_version=claims.get("policy_version"),
            reason_code=claims.get("reason_code")
        )

        return public_alert_id

class DashboardDataService:
    """Service boundary for dashboard read-only database queries."""

    def __init__(self, device_qs, traffic_qs, threat_qs):
        self.device_qs = device_qs
        self.traffic_qs = traffic_qs
        self.threat_qs = threat_qs

    def _safe_paginate(self, page, size, max_size=100):
        try:
            page = int(page) if page else 1
            size = int(size) if size else 20
        except ValueError:
            page, size = 1, 20

        page = max(1, page)
        size = min(max_size, max(1, size))
        return page, size

    def get_devices(self, page=1, size=20) -> dict:
        page, size = self._safe_paginate(page, size)
        try:
            # We assume get_devices returns paginated results or a list
            # We'll just fetch devices safely.
            devices = self.device_qs.get_devices(page=page, page_size=size)
            return {"records": devices.get('items', []), "total": devices.get('total', 0), "page": page, "size": size, "error": None}
        except Exception as e:
            logger.error("Dashboard failed to fetch devices: %s", str(e))
            return {"records": [], "total": 0, "page": page, "size": size, "error": "Device service unavailable"}

    def get_device(self, device_id: str) -> dict:
        try:
            device = self.device_qs.get_device_by_id(device_id)
            return {"item": device, "error": None if device else "Device not found"}
        except Exception as e:
            logger.error("Dashboard failed to fetch device: %s", str(e))
            return {"item": None, "error": "Device service unavailable"}

    def get_traffic(self, page=1, size=20) -> dict:
        page, size = self._safe_paginate(page, size)
        try:
            traffic = self.traffic_qs.get_recent_traffic(page=page, page_size=size)
            return {"records": traffic.get('items', []), "total": traffic.get('total', 0), "page": page, "size": size, "error": None}
        except Exception as e:
            logger.error("Dashboard failed to fetch traffic: %s", str(e))
            return {"records": [], "total": 0, "page": page, "size": size, "error": "Traffic service unavailable"}

    def get_traffic_record(self, record_id: int) -> dict:
        try:
            traffic = self.traffic_qs.get_traffic_by_id(record_id)
            return {"item": traffic, "error": None if traffic else "Traffic record not found"}
        except Exception as e:
            logger.error("Dashboard failed to fetch traffic record: %s", str(e))
            return {"item": None, "error": "Traffic service unavailable"}

    def get_threats(self, page=1, size=20) -> dict:
        page, size = self._safe_paginate(page, size)
        try:
            threats = self.threat_qs.get_recent_threats(page=page, page_size=size)
            return {"records": threats.get('items', []), "total": threats.get('total', 0), "page": page, "size": size, "error": None}
        except Exception as e:
            logger.error("Dashboard failed to fetch threats: %s", str(e))
            return {"records": [], "total": 0, "page": page, "size": size, "error": "Threat service unavailable"}

    def get_threat(self, threat_id: int) -> dict:
        try:
            threat = self.threat_qs.get_threat_by_id(threat_id)
            return {"item": threat, "error": None if threat else "Threat not found"}
        except Exception as e:
            logger.error("Dashboard failed to fetch threat: %s", str(e))
            return {"item": None, "error": "Threat service unavailable"}

class DashboardInferenceService:
    """Service boundary for dashboard inference requests."""

    def __init__(self, inference_service):
        self.inference_service = inference_service

    def predict_flow(self, features: dict) -> dict:
        """Safely run single-flow inference from the dashboard."""
        try:
            # We assume features have already been validated by the route
            result = self.inference_service.predict_flow(features)
            return {"result": result, "error": None}
        except Exception as e:
            logger.error("Dashboard single-flow inference failed: %s", str(e))
            # Catch backend service unavailable or inference failures
            return {"result": None, "error": str(e)}

    def predict_flows(self, batch_features: list) -> dict:
        """Safely run batch-flow inference from the dashboard."""
        try:
            result = self.inference_service.predict_flows(batch_features)
            return {"result": result, "error": None}
        except Exception as e:
            logger.error("Dashboard batch-flow inference failed: %s", str(e))
            return {"result": None, "error": str(e)}

class DashboardAlertService:
    """Service boundary for dashboard alerts and lifecycle actions."""

    def __init__(self, alert_persistence_service):
        self.persistence = alert_persistence_service

    def get_alerts(self, page=1, size=20, filters=None) -> dict:
        try:
            page = int(page) if page else 1
            size = int(size) if size else 20
        except ValueError:
            page, size = 1, 20

        page = max(1, page)
        size = min(100, max(1, size))

        if filters is None:
            filters = {}

        try:
            result = self.persistence.get_alerts(page=page, page_size=size, filters=filters)
            return {"result": result, "error": None}
        except Exception as e:
            logger.error("Dashboard failed to fetch alerts: %s", str(e))
            return {"result": None, "error": "Alerts service unavailable"}

    def get_alert(self, public_alert_id: str) -> dict:
        try:
            alert = self.persistence.get_alert(public_alert_id)
            if not alert:
                return {"result": None, "error": "Alert not found", "status_code": 404}
            return {"result": alert, "error": None}
        except Exception as e:
            logger.error("Dashboard failed to fetch alert detail: %s", str(e))
            return {"result": None, "error": "Alerts service unavailable", "status_code": 503}

    def transition_alert(self, public_alert_id: str, target_status: str, expected_version: int) -> dict:
        from utils.time_utils import get_current_utc_time
        from utils.exceptions import NotFoundError, ConflictError, ApplicationError

        timestamp = get_current_utc_time().isoformat()

        try:
            alert = self.persistence.transition_alert(
                public_alert_id=public_alert_id,
                target_status=target_status,
                timestamp=timestamp,
                expected_version=expected_version
            )
            return {"result": alert, "error": None}
        except NotFoundError as e:
            return {"result": None, "error": str(e), "status_code": 404}
        except ConflictError as e:
            return {"result": None, "error": str(e), "status_code": 409}
        except ApplicationError as e:
            return {"result": None, "error": str(e), "status_code": 400}
        except Exception as e:
            logger.error("Dashboard failed to transition alert: %s", str(e))
            return {"result": None, "error": "Alerts service unavailable", "status_code": 503}
