"""Framework-neutral owner of capture lifecycle, worker, queue, and summaries."""
from datetime import datetime, timezone
import logging
import queue
import threading
import time
import uuid

from .capture_config import CaptureConfig
from .capture_exceptions import (
    CaptureAlreadyRunningError, CaptureDisabledError, CaptureError,
    CaptureErrorCategory, CaptureNotRunningError, CaptureSourceInitializationError,
    CaptureStopTimeoutError,
)
from .capture_models import (
    CapturedPacketMetadata, CaptureSessionSummary, CaptureStatusSnapshot,
)
from .constants import CaptureState


class CaptureService:
    def __init__(self, config: CaptureConfig, source_factory, interface_discovery,
                 logger=None, clock=None):
        self._config, self._source_factory = config, source_factory
        self._interfaces = interface_discovery
        self._logger = logger or logging.getLogger(__name__)
        self._clock = clock or time.monotonic
        self._state = CaptureState.DISABLED if not config.enabled else CaptureState.STOPPED
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._metadata_queue = queue.Queue(maxsize=config.queue_size)
        self._worker = self._source = None
        self._session_id = self._interface_key = None
        self._packet_count = self._dropped_count = 0
        self._selected_device_ips = None
        self._started_mono = None
        self._start_timestamp = self._stop_timestamp = None
        self._stop_reason = self._error_category = None
        self._summary = None

    def start_capture(self, safe_interface_key, selected_device_ips=None):
        with self._lock:
            self._reap_completed()
            if not self._config.enabled:
                raise CaptureDisabledError("Capture is disabled")
            if self._state not in (CaptureState.STOPPED,):
                raise CaptureAlreadyRunningError("Capture lifecycle is busy")
            native = self._interfaces.resolve(safe_interface_key)
            self._state = CaptureState.STARTING
            try:
                source = self._source_factory(self._config, native, safe_interface_key)
                source.open(native, self._config)
            except CaptureError:
                self._state = CaptureState.STOPPED
                raise
            except Exception as exc:
                self._state = CaptureState.STOPPED
                raise CaptureSourceInitializationError("Capture source could not be opened") from exc
            while True:
                try:
                    self._metadata_queue.get_nowait()
                except queue.Empty:
                    break
            self._source = source
            self._session_id, self._interface_key = str(uuid.uuid4()), safe_interface_key
            self._packet_count = self._dropped_count = 0
            self._selected_device_ips = (
                frozenset(str(value).strip() for value in selected_device_ips if str(value).strip())
                if selected_device_ips is not None else None
            )
            self._stop_reason = self._error_category = self._summary = None
            self._started_mono = self._clock()
            self._start_timestamp, self._stop_timestamp = datetime.now(timezone.utc), None
            self._stop_event.clear()
            self._state = CaptureState.RUNNING
            self._worker = threading.Thread(
                target=self._run_worker, name=f"CaptureWorker-{self._session_id[:8]}", daemon=False
            )
            self._worker.start()

    def stop_capture(self):
        with self._lock:
            retry = self._state is CaptureState.ERROR and self._error_category == "stop_timeout"
            if self._state not in (CaptureState.RUNNING, CaptureState.STARTING) and not retry:
                raise CaptureNotRunningError("Capture is not running")
            self._state = CaptureState.STOPPING
            self._stop_event.set()
            worker, source = self._worker, self._source
            if source:
                source.request_stop()
        if worker:
            worker.join(self._config.stop_join_timeout_seconds)
        with self._lock:
            if worker and worker.is_alive():
                self._state, self._stop_reason = CaptureState.ERROR, "stop_timeout"
                self._error_category = "stop_timeout"
                raise CaptureStopTimeoutError("Capture worker did not stop")
            if source:
                source.close()
            self._complete("user_requested")
            self._worker = self._source = None

    def shutdown(self):
        try:
            if self._worker:
                self.stop_capture()
        except CaptureError:
            return False
        return True

    def status_snapshot(self):
        with self._lock:
            self._reap_completed()
            elapsed = 0.0 if self._started_mono is None else max(0.0, self._clock() - self._started_mono)
            return CaptureStatusSnapshot(
                self._config.enabled, self._config.source, self._state, self._session_id,
                self._interface_key, self._packet_count, self._dropped_count,
                self._start_timestamp, elapsed, self._stop_reason, self._error_category
            )

    def _reap_completed(self):
        if self._worker is not None and not self._worker.is_alive():
            self._worker = None
            if self._state is not CaptureState.ERROR:
                self._source = None

    def final_summary(self):
        return self._summary

    @staticmethod
    def _validate_limit(limit):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be a positive integer")

    def get_metadata_snapshot(self, limit):
        self._validate_limit(limit)
        with self._metadata_queue.mutex:
            return tuple(list(self._metadata_queue.queue)[:limit])

    def drain_metadata(self, limit):
        self._validate_limit(limit)
        values = []
        for _ in range(limit):
            try:
                values.append(self._metadata_queue.get_nowait())
            except queue.Empty:
                break
        return tuple(values)

    def _run_worker(self):
        try:
            while not self._stop_event.is_set():
                if self._config.max_packets is not None and self._packet_count >= self._config.max_packets:
                    self._complete("packet_limit_reached")
                    return
                if (self._config.max_duration_seconds is not None
                        and self._clock() - self._started_mono >= self._config.max_duration_seconds):
                    self._complete("duration_limit_reached")
                    return
                metadata = self._source.read_metadata(self._config.read_timeout_seconds)
                if metadata is None:
                    continue
                if not isinstance(metadata, CapturedPacketMetadata):
                    raise TypeError("source returned unsafe metadata")
                if (self._selected_device_ips is not None
                        and metadata.endpoint_metadata is not None):
                    endpoints = {
                        metadata.endpoint_metadata.source_ip,
                        metadata.endpoint_metadata.destination_ip,
                    }
                    if not endpoints.intersection(self._selected_device_ips):
                        continue
                self._packet_count += 1
                try:
                    self._metadata_queue.put_nowait(metadata)
                except queue.Full:
                    self._dropped_count += 1
        except Exception as exc:
            with self._lock:
                category = (
                    exc.category.name if isinstance(exc, CaptureError) else "capture_failed"
                )
                underlying = exc.__cause__ or exc
                self._logger.warning(
                    "Capture source read interrupted: category=%s exception=%s message=%s",
                    category, type(underlying).__name__, str(underlying)[:512],
                    extra={"capture_source_error": True},
                )
                # A source may report the interruption caused by request_stop
                # as an exception (for example, while an Npcap read is being
                # torn down).  That is a normal shutdown path, not a source
                # failure.  Never allow a worker to regress a completed stop.
                if self._stop_event.is_set() or self._state in (
                    CaptureState.STOPPING, CaptureState.STOPPED,
                ):
                    return
                self._state = CaptureState.ERROR
                self._error_category = category
                self._stop_reason = "source_error"
        finally:
            with self._lock:
                should_close = self._state is not CaptureState.ERROR
                source = self._source
            if should_close and source:
                try:
                    source.close()
                except Exception as exc:
                    self._logger.info(
                        "Capture source close completed with interruption: "
                        "exception=%s message=%s",
                        type(exc).__name__, str(exc)[:512],
                        extra={"capture_source_shutdown": True},
                    )

    def _complete(self, reason):
        with self._lock:
            # Completion is terminal for a session.  In particular, a late
            # worker callback must not turn a successful stop into ERROR.
            if self._state is CaptureState.STOPPED:
                return
            self._state, self._stop_reason, self._error_category = (
                CaptureState.STOPPED, reason, None
            )
            self._stop_timestamp = datetime.now(timezone.utc)
            duration = (0.0 if self._started_mono is None else
                        max(0.0, self._clock() - self._started_mono))
            if self._session_id:
                self._summary = CaptureSessionSummary(
                    self._session_id, self._interface_key, self._start_timestamp,
                    self._stop_timestamp, CaptureState.STOPPED, self._packet_count,
                    self._dropped_count, reason, None, duration,
                    self._config.limits_snapshot()
                )
