class ReadinessService:
    def __init__(self, config_service, migration_service, capability_service,
                 database_probe):
        self._config = config_service
        self._migrations = migration_service
        self._capabilities = capability_service
        self._database_probe = database_probe

    def check(self, config):
        validation = self._config.validate(config)
        migration = self._migrations.inspect()
        try:
            database_ready = bool(self._database_probe())
        except Exception:
            database_ready = False
        capabilities = self._capabilities.inspect(config)
        capture_ready = next(
            item.available for item in capabilities
            if item.name == "capture_lifecycle_and_metadata_queue"
        )
        strict = bool(config.get("MIGRATION_STRICT"))
        ready = (
            validation.ready and database_ready and capture_ready
            and (not strict or not migration.migration_required)
        )
        return {
            "status": "ready" if ready else "not_ready",
            "components": {
                "configuration": "ready" if validation.ready else "failed",
                "database": "ready" if database_ready else "failed",
                "migrations": migration.status,
                "runtime_capabilities": "ready" if capture_ready else "failed",
            },
            "warnings": validation.warnings,
        }
