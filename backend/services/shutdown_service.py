import threading


class ShutdownCoordinator:
    def __init__(self, capture_service, notification_provider,
                 defensive_provider, database_disposer, logger=None):
        self._resources = (
            ("capture", getattr(capture_service, "shutdown", None)),
            ("notification_provider", getattr(notification_provider, "close", None)),
            ("defensive_provider", getattr(defensive_provider, "close", None)),
        )
        self._database_disposer = database_disposer
        self._logger = logger
        self._lock = threading.Lock()
        self._closed = False

    def shutdown(self):
        with self._lock:
            if self._closed:
                return True
            self._closed = True
        for name, close in self._resources:
            if close:
                try:
                    close()
                except Exception:
                    if self._logger:
                        self._logger.warning(
                            "Resource shutdown failed safely: %s", name
                        )
        try:
            self._database_disposer()
        except Exception:
            if self._logger:
                self._logger.warning("Database disposal failed safely.")
        return True
