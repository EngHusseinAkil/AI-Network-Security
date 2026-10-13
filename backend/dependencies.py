"""
Lightweight application dependency container.
"""
import logging
from pathlib import Path
from backend.services.health_service import HealthService
from backend.services.version_service import VersionService
from backend.services.ai_health_service import AIHealthService
from backend.services.model_service import ModelService

from backend.services.inference_service import InferenceService
from backend.services.db_services import DeviceQueryService, TrafficQueryService, ThreatQueryService
from backend.services.backend_health_service import BackendHealthService

logger = logging.getLogger(__name__)

class DependencyContainer:
    """
    Holds references to services and components.
    For this milestone, we instantiate DB Query Services.
    """
    def __init__(self, config=None):
        # Keep the resolved application configuration supplied by the factory.
        # In particular, capture settings must come from Flask's app.config so
        # factory overrides reach the real CaptureService instance.
        config = config if config is not None else {}
        self.config = config
        models_dir = Path(config.get("MODELS_DIR", "models"))
        registry_path = str(
            config.get("MODEL_REGISTRY_PATH", models_dir / "registry.json")
        )
        self.health_service = HealthService()
        self.version_service = VersionService(api_version="v1")
        self.ai_health_service = AIHealthService(registry_path, str(models_dir))
        self.model_service = ModelService(registry_path)
        self.inference_service = InferenceService(registry_path)
        self.backend_health_service = BackendHealthService()

        from auth.authorization import AuthorizationService
        from backend.services.user_account_service import UserAccountService
        from backend.services.security_audit_service import SecurityAuditService
        self.authorization_service = AuthorizationService()
        self.user_account_service = UserAccountService(self.authorization_service)
        self.security_audit_service = SecurityAuditService()

        # Read-Only Database Services
        self.device_query_service = DeviceQueryService()
        self.traffic_query_service = TrafficQueryService()
        self.threat_query_service = ThreatQueryService()

        from backend.services.alert_persistence_service import AlertPersistenceService
        self.alert_persistence_service = AlertPersistenceService()
        from notifications.config import AlertNotificationConfig
        from notifications.providers import (
            FakeNotificationProvider, UnavailableEmailProvider,
        )
        from backend.services.notification_delivery_service import (
            NotificationDeliveryService,
        )
        from backend.services.alert_notification_service import AlertNotificationService
        from dashboard.alert_notification_service import (
            DashboardAlertNotificationService,
        )

        notification_config = config
        provider_name = notification_config.get(
            "ALERT_NOTIFICATION_PROVIDER", "email"
        )
        fake_permitted = bool(
            notification_config.get("TESTING")
            or notification_config.get("ALERT_NOTIFICATION_DEMO_ENABLED")
        )
        self.alert_notification_config = AlertNotificationConfig(
            enabled=bool(notification_config.get("ALERT_NOTIFICATIONS_ENABLED", False)),
            provider=provider_name,
            recipient=notification_config.get("ALERT_NOTIFICATION_RECIPIENT"),
            recipient_label=notification_config.get(
                "ALERT_NOTIFICATION_RECIPIENT_LABEL",
                "Configured security mailbox",
            ),
            fake_provider_permitted=fake_permitted,
            provider_timeout_seconds=notification_config.get(
                "ALERT_NOTIFICATION_TIMEOUT_SECONDS", 10.0
            ),
        )
        self.notification_provider = (
            FakeNotificationProvider(notification_config.get(
                "ALERT_NOTIFICATION_FAKE_OUTCOME", "sent"
            )) if provider_name == "fake" else UnavailableEmailProvider()
        )
        self.notification_delivery_service = NotificationDeliveryService()
        self.alert_notification_service = AlertNotificationService(
            self.alert_notification_config,
            self.notification_provider,
            self.alert_persistence_service,
            self.notification_delivery_service,
            notification_config.get(
                "SECRET_KEY", "super-secret-placeholder-key-for-development"
            ),
        )
        self.dashboard_alert_notification_service = (
            DashboardAlertNotificationService(
                self.alert_notification_service,
                self.notification_delivery_service,
            )
        )

        from defense.config import DefensiveActionConfig
        from defense.providers import (
            FakeDefensiveActionProvider, UnavailableDefensiveActionProvider,
        )
        from defense.resolver import TrustedDefensiveTargetResolver
        from backend.services.defensive_action_persistence_service import (
            DefensiveActionPersistenceService,
        )
        from backend.services.defensive_action_service import DefensiveActionService
        from dashboard.defensive_action_service import DashboardDefensiveActionService

        defense_provider_name = notification_config.get(
            "DEFENSIVE_ACTION_PROVIDER", "unavailable"
        )
        defense_fake_permitted = bool(
            notification_config.get("TESTING")
            or notification_config.get("DEFENSIVE_ACTION_DEMO_ENABLED")
        )
        self.defensive_action_config = DefensiveActionConfig(
            enabled=bool(notification_config.get("DEFENSIVE_ACTIONS_ENABLED", False)),
            provider=defense_provider_name,
            fake_provider_permitted=defense_fake_permitted,
            default_duration_seconds=notification_config.get(
                "DEFENSIVE_ACTION_DEFAULT_DURATION_SECONDS", 900
            ),
            maximum_duration_seconds=notification_config.get(
                "DEFENSIVE_ACTION_MAXIMUM_DURATION_SECONDS", 86_400
            ),
        )
        self.defensive_target_resolver = TrustedDefensiveTargetResolver(
            notification_config.get("DEFENSIVE_ACTION_TARGETS")
        )
        self.defensive_action_provider = (
            FakeDefensiveActionProvider(
                notification_config.get("DEFENSIVE_ACTION_FAKE_OUTCOME", "applied"),
                notification_config.get(
                    "DEFENSIVE_ACTION_FAKE_REMOVE_OUTCOME", "removed"
                ),
            )
            if defense_provider_name == "fake"
            else UnavailableDefensiveActionProvider()
        )
        self.defensive_action_persistence_service = DefensiveActionPersistenceService()
        self.defensive_action_service = DefensiveActionService(
            self.defensive_action_config,
            self.defensive_target_resolver,
            self.defensive_action_provider,
            self.alert_persistence_service,
            self.defensive_action_persistence_service,
            notification_config.get(
                "SECRET_KEY", "super-secret-placeholder-key-for-development"
            ),
        )
        self.dashboard_defensive_action_service = DashboardDefensiveActionService(
            self.defensive_action_service,
            self.defensive_action_persistence_service,
        )

        from alerts.policy import AlertPolicy, ThresholdConfig
        if (
            config.get("ENVIRONMENT") == "development"
            and config.get("DEMO_MODE") is True
            and config.get("CAPTURE_SOURCE") == "fake"
            and config.get("CAPTURE_DEMO_ENABLED") is True
        ):
            # The tiny demo model's calibrated scores are intentionally low;
            # keep the normal policy path but lower only this demo threshold.
            self.alert_policy = AlertPolicy(ThresholdConfig(min_confidence=0.30))
        else:
            self.alert_policy = AlertPolicy()

        # Dashboard Services
        from dashboard.services import (
            DashboardHealthService,
            DashboardModelService,
            DashboardDataService,
            DashboardInferenceService,
            DashboardAlertService,
            DashboardAlertEvaluationService,
            DashboardAlertCreationService
        )
        self.dashboard_health_service = DashboardHealthService(
            self.health_service,
            self.ai_health_service,
            self.backend_health_service
        )
        self.dashboard_model_service = DashboardModelService(self.model_service)
        self.dashboard_alert_evaluation_service = DashboardAlertEvaluationService(self.alert_policy)
        self.dashboard_alert_creation_service = DashboardAlertCreationService(self.alert_persistence_service)
        self.dashboard_data_service = DashboardDataService(
            self.device_query_service,
            self.traffic_query_service,
            self.threat_query_service
        )
        self.dashboard_inference_service = DashboardInferenceService(self.inference_service)
        self.dashboard_alert_service = DashboardAlertService(self.alert_persistence_service)

        # Monitoring State Service (read-only; no threads, no I/O at init time)
        from backend.services.monitoring_service import MonitoringStateService
        self.monitoring_service = MonitoringStateService(
            ai_health_svc=self.ai_health_service,
            model_svc=self.model_service,
        )

        from backend.services.monitoring_simulation_service import MonitoringSimulationService
        self.monitoring_simulation_service = MonitoringSimulationService(
            inference_service=self.inference_service,
            alert_policy=self.alert_policy,
            monitoring_state_service=self.monitoring_service
        )

        from backend.services.simulation_evaluation_report_service import SimulationEvaluationReportService
        self.simulation_evaluation_report_service = SimulationEvaluationReportService(
            monitoring_state_service=self.monitoring_service
        )

        # Keep db_session None for tests/external configs as we use session_scope
        self.db_session = None

        self._configure_capture(config or {})

        from database.connection import dispose_engine, get_engine, test_connection
        from backend.services.production_config_service import ProductionConfigService
        from backend.services.migration_health_service import MigrationHealthService
        from backend.services.runtime_capability_service import RuntimeCapabilityService
        from backend.services.request_id_service import RequestIdService
        from backend.services.readiness_service import ReadinessService
        from backend.services.shutdown_service import ShutdownCoordinator
        self.production_config_service = ProductionConfigService()
        self.migration_health_service = MigrationHealthService(get_engine)
        self.runtime_capability_service = RuntimeCapabilityService()
        self.request_id_service = RequestIdService()
        self.readiness_service = ReadinessService(
            self.production_config_service,
            self.migration_health_service,
            self.runtime_capability_service,
            test_connection,
        )
        self.shutdown_coordinator = ShutdownCoordinator(
            self.capture_service, self.notification_provider,
            self.defensive_action_provider, dispose_engine, logger,
        )

    def _configure_capture(self, config):
        from network.capture_config import CaptureConfig
        from network.capture_service import CaptureService
        from network.interfaces import InterfaceDiscoveryService
        from dashboard.capture_service import DashboardCaptureService

        fake_permitted = bool(config.get("TESTING") or config.get("CAPTURE_DEMO_ENABLED"))
        capture_config = CaptureConfig(
            enabled=bool(config.get("CAPTURE_ENABLED", False)),
            source=config.get("CAPTURE_SOURCE", "scapy"),
            fake_source_permitted=fake_permitted,
            max_packets=config.get("CAPTURE_MAX_PACKETS"),
            max_duration_seconds=config.get("CAPTURE_MAX_DURATION_SECONDS"),
            queue_size=config.get("CAPTURE_QUEUE_SIZE", 1024),
            capture_filter=config.get("CAPTURE_FILTER"),
            promiscuous=config.get("CAPTURE_PROMISCUOUS", True),
            read_timeout_seconds=config.get("CAPTURE_READ_TIMEOUT_SECONDS", 1.0),
            stop_join_timeout_seconds=config.get("CAPTURE_STOP_JOIN_TIMEOUT_SECONDS", 5.0),
        )
        self.interface_discovery_service = InterfaceDiscoveryService(logger=logger)

        def source_factory(cfg, native, safe_key):
            if cfg.source == "fake":
                from network.fake_source import FakePacketSource, metadata_for_config
                return FakePacketSource(
                    metadata_for_config(config, cfg, safe_key)
                )
            from network.adapters.scapy_adapter import ScapyPacketSource
            return ScapyPacketSource(
                safe_key, config.get("LIVE_LOCAL_NETWORK_CIDR")
            )

        def provider_factory():
            if capture_config.source == "fake":
                class FakeProvider:
                    def discover_interfaces(self):
                        return (("fake0", "Simulated capture"),)
                return FakeProvider()
            from network.adapters.scapy_adapter import ScapyHotspotInterfaceProvider
            return ScapyHotspotInterfaceProvider(config.get("LIVE_LOCAL_NETWORK_CIDR"))

        self.capture_service = CaptureService(
            capture_config, source_factory, self.interface_discovery_service, logger=logger
        )
        self.dashboard_capture_service = DashboardCaptureService(
            self.capture_service, self.interface_discovery_service, provider_factory,
            local_network_cidr=config.get("LIVE_LOCAL_NETWORK_CIDR"),
        )

        from network.flow_config import MetadataFlowConfig
        from network.flow_aggregation_service import FlowAggregationService
        from network.flow_feature_service import FlowFeatureService
        from network.capture_flow_processor import CaptureFlowProcessor
        from dashboard.flow_processing_service import DashboardFlowProcessingService

        self.flow_config = MetadataFlowConfig(
            aggregation_window_seconds=config.get("FLOW_AGGREGATION_WINDOW_SECONDS", 5.0),
            inactivity_timeout_seconds=config.get("FLOW_INACTIVITY_TIMEOUT_SECONDS", 10.0),
            max_active_flows=config.get("FLOW_MAX_ACTIVE", 1_000),
            max_completed_flows=config.get("FLOW_MAX_COMPLETED", 1_000),
            max_packets_per_flow=config.get("FLOW_MAX_PACKETS", 10_000),
            max_flow_duration_seconds=config.get("FLOW_MAX_DURATION_SECONDS", 60.0),
            max_processing_batch=config.get("FLOW_PROCESSING_BATCH_SIZE", 1_024),
        )
        self.flow_aggregation_service = FlowAggregationService(self.flow_config)
        self.flow_feature_service = FlowFeatureService()
        self.capture_flow_processor = CaptureFlowProcessor(
            self.capture_service, self.flow_aggregation_service,
            self.flow_feature_service, self.flow_config,
        )
        self.dashboard_flow_processing_service = DashboardFlowProcessingService(
            self.capture_flow_processor, self.flow_aggregation_service
        )

        from network.live_flow_evaluation_config import LiveFlowEvaluationConfig
        from network.live_flow_evaluation_state import LiveFlowEvaluationStateService
        from backend.services.live_flow_evaluation_service import LiveFlowEvaluationService
        from backend.services.live_flow_alert_creation_service import (
            LiveFlowAlertCreationService,
        )
        from dashboard.live_flow_evaluation_service import DashboardLiveFlowEvaluationService

        self.live_flow_evaluation_config = LiveFlowEvaluationConfig(
            max_flows_per_request=config.get("LIVE_FLOW_EVALUATION_BATCH_SIZE", 100),
            max_retained_evaluations=config.get("LIVE_FLOW_EVALUATION_HISTORY_SIZE", 1_000),
            max_retry_count=config.get("LIVE_FLOW_EVALUATION_MAX_RETRIES", 1),
            schema_version=config.get(
                "LIVE_FLOW_EVALUATION_SCHEMA_VERSION", "live-flow-evaluation-v1"
            ),
        )
        self.live_flow_evaluation_state_service = LiveFlowEvaluationStateService(
            self.live_flow_evaluation_config
        )
        self.live_flow_evaluation_service = LiveFlowEvaluationService(
            self.flow_aggregation_service,
            self.flow_feature_service,
            self.inference_service,
            self.alert_policy,
            self.live_flow_evaluation_state_service,
            self.live_flow_evaluation_config,
            logger=logger,
        )
        self.live_flow_alert_creation_service = LiveFlowAlertCreationService(
            config.get(
                "SECRET_KEY", "super-secret-placeholder-key-for-development"
            ),
            self.live_flow_evaluation_state_service,
            self.alert_persistence_service,
            self.live_flow_evaluation_config.schema_version,
        )
        self.dashboard_live_flow_evaluation_service = DashboardLiveFlowEvaluationService(
            self.live_flow_evaluation_service,
            self.live_flow_evaluation_state_service,
            self.flow_aggregation_service,
            self.live_flow_alert_creation_service,
        )
