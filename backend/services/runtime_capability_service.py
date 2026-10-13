from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuntimeCapability:
    name: str
    classification: str
    available: bool


class RuntimeCapabilityService:
    def inspect(self, config):
        workers = config.get("WEB_WORKER_COUNT", 1)
        capture_enabled = bool(config.get("CAPTURE_ENABLED"))
        return (
            RuntimeCapability("interface_discovery_cache", "worker_local", True),
            RuntimeCapability(
                "capture_lifecycle_and_metadata_queue", "single_owner",
                not capture_enabled or workers == 1,
            ),
            RuntimeCapability("flow_aggregation", "worker_local_reconstructable", True),
            RuntimeCapability("evaluation_history", "worker_local_reconstructable", True),
            RuntimeCapability("login_rate_limits", "durable_account_lockout", True),
            RuntimeCapability("http_rate_limits", "worker_local", True),
            RuntimeCapability("session_storage", "signed_client_cookie", True),
            RuntimeCapability("durable_action_idempotency", "database_shared", True),
        )
