"""
Monitoring State Service.

Provides a read-only, deterministic view of monitoring subsystem state.
This milestone establishes the state abstraction only.

Design constraints
------------------
* Pure Python — no threads, no schedulers, no I/O at import or init time.
* State is computed from existing dependency services on demand; nothing is
  persisted or cached between requests.
* Counters are zero until a real monitoring engine writes them; fabricated
  counts are explicitly forbidden.
* Unknown state tokens are mapped safely through an allowlist; arbitrary
  strings are never passed to templates as CSS classes.
"""

import logging
from typing import Dict, Any, Optional, List
import collections
from backend.schemas.monitoring import SimulationHistoryRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State constants
# ---------------------------------------------------------------------------

class MonitoringState:
    """
    Allowlist of valid monitoring state tokens.

    These are the only values that should appear as ``state`` in the
    monitoring status contract.  Any value not in this set is remapped to
    ``UNKNOWN`` by :func:`safe_state`.
    """
    DISABLED       = "disabled"
    IDLE           = "idle"
    STARTING       = "starting"
    RUNNING        = "running"
    DEGRADED       = "degraded"
    STOPPED        = "stopped"
    ERROR          = "error"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN        = "unknown"

    SIMULATION_COMPLETE = "simulation_complete"

    # Frozenset for fast membership testing
    _ALL = frozenset({
        DISABLED, IDLE, STARTING, RUNNING,
        DEGRADED, STOPPED, ERROR, NOT_CONFIGURED, UNKNOWN,
        SIMULATION_COMPLETE,
    })

    @classmethod
    def safe_state(cls, raw: Optional[str]) -> str:
        """
        Return *raw* if it is a known state token, otherwise return UNKNOWN.

        Never passes arbitrary strings to the caller; safe for use as a CSS
        class suffix or aria-label content.
        """
        if isinstance(raw, str) and raw in cls._ALL:
            return raw
        return cls.UNKNOWN


# ---------------------------------------------------------------------------
# Status contract helpers
# ---------------------------------------------------------------------------

def _safe_str(value: Any, default: str = "—") -> str:
    """Return *value* as a stripped string, or *default* if absent/None."""
    if value is None:
        return default
    s = str(value).strip()
    return s if s else default


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class MonitoringStateService:
    """
    Read-only service that exposes a safe monitoring-state snapshot.

    The service does not start any background threads, schedulers, or
    monitoring loops — not at construction, not at import, not ever.

    It consults existing health and model services to populate health-summary
    and active-model-version fields.  All counts start at zero; fabricated
    counts are forbidden.

    Parameters
    ----------
    ai_health_svc :
        A service with ``get_health_summary() -> dict`` (AIHealthService or
        compatible duck-type).  May be None; missing fields degrade gracefully.
    model_svc :
        A service with ``get_active_model() -> dict`` (ModelService or
        compatible duck-type).  May be None; missing fields degrade gracefully.
    """

    def __init__(self, ai_health_svc=None, model_svc=None, simulation_history_limit: int = 100) -> None:
        import threading
        self._ai_health_svc = ai_health_svc
        self._model_svc = model_svc

        try:
            self._simulation_history_limit = max(1, int(simulation_history_limit))
        except (ValueError, TypeError):
            self._simulation_history_limit = 100

        self._lock = threading.Lock()

        # Bounded in-memory state for simulation
        self._state = MonitoringState.DISABLED
        self._last_successful_cycle = None
        self._last_error_category = None
        self._latest_simulation_result = None
        self._history = collections.deque(maxlen=self._simulation_history_limit)

        # Explicit simulation counters
        self._simulation_cycle_count = 0
        self._simulated_flow_count = 0
        self._successful_simulation_inference_count = 0
        self._failed_simulation_inference_count = 0
        self._simulation_recommendation_count = 0

    # ------------------------------------------------------------------
    # State mutators (for explicit simulation orchestration)
    # ------------------------------------------------------------------

    def update_simulation_start(self) -> None:
        """Mark the simulation as running safely."""
        with self._lock:
            self._state = MonitoringState.RUNNING

    def update_simulation_success(self, result: Dict[str, Any], timestamp: str, recommended_alert: bool, history_record: SimulationHistoryRecord) -> None:
        """Atomically record a successful simulation cycle."""
        with self._lock:
            self._state = MonitoringState.SIMULATION_COMPLETE
            self._last_successful_cycle = timestamp
            self._latest_simulation_result = result
            self._simulation_cycle_count += 1
            self._simulated_flow_count += 1
            self._successful_simulation_inference_count += 1
            if recommended_alert:
                self._simulation_recommendation_count += 1
            self._last_error_category = None
            self._history.append(history_record)

    def update_simulation_error(self, error_category: str, history_record: SimulationHistoryRecord) -> None:
        """Atomically record a simulation cycle that failed after inference."""
        with self._lock:
            self._state = MonitoringState.ERROR
            self._last_error_category = error_category
            self._simulation_cycle_count += 1
            self._simulated_flow_count += 1
            # Note: failed_simulation_inference_count is not incremented here since inference succeeded.
            self._history.append(history_record)

    def update_simulation_inference_failure(self, error_category: str, history_record: SimulationHistoryRecord) -> None:
        """Atomically record an inference failure during simulation."""
        with self._lock:
            self._state = MonitoringState.ERROR
            self._last_error_category = error_category
            self._simulation_cycle_count += 1
            self._simulated_flow_count += 1
            self._failed_simulation_inference_count += 1
            self._history.append(history_record)

    def clear_running_state(self) -> None:
        """Ensure state doesn't remain permanently running on exception."""
        with self._lock:
            if self._state == MonitoringState.RUNNING:
                self._state = MonitoringState.ERROR
                if not self._last_error_category:
                    self._last_error_category = "unexpected_simulation_failure"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_ai_health_summary(self) -> Dict[str, Any]:
        """Safely fetch a minimal AI health summary, never raising."""
        if self._ai_health_svc is None:
            return {"overall_status": "unknown", "readiness_level": "unknown"}
        try:
            summary = self._ai_health_svc.get_health_summary()
            return {
                "overall_status": _safe_str(summary.get("overall_status"), "unknown"),
                "readiness_level": _safe_str(summary.get("readiness_level"), "unknown"),
            }
        except Exception as exc:
            logger.warning("MonitoringStateService: AI health fetch failed: %s", exc)
            return {"overall_status": "unknown", "readiness_level": "unknown"}

    def _get_active_model_version(self) -> Optional[str]:
        """Safely fetch the active model version string, never raising."""
        if self._model_svc is None:
            return None
        try:
            data = self._model_svc.get_active_model()
            model_block = data.get("model") or {}
            version = model_block.get("model_version")
            return _safe_str(version, None) if version else None
        except Exception as exc:
            logger.warning("MonitoringStateService: model version fetch failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_simulation_history(self, page: int = 1, page_size: int = 10) -> tuple[List[SimulationHistoryRecord], int]:
        """
        Return a paginated list of simulation history records (newest first).
        Raises ValueError if page < 1 or page_size < 1.
        Returns a tuple: (records_for_page, total_retained_count).
        """
        if page < 1 or page_size < 1:
            raise ValueError("Page and page_size must be >= 1")

        with self._lock:
            # Create a snapshot in newest-first order
            history_snapshot = list(reversed(self._history))
            total_count = len(history_snapshot)

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        return history_snapshot[start_idx:end_idx], total_count

    def get_simulation_cycle(self, cycle_id: str) -> Optional[SimulationHistoryRecord]:
        """Return a single simulation history record by cycle_id, or None."""
        with self._lock:
            # We iterate to find the item.
            # For O(1) we could use a dict, but maxlen is 100, so O(N) is trivial.
            for record in self._history:
                if record.cycle_id == cycle_id:
                    return record
        return None

    def get_history_limit(self) -> int:
        return self._simulation_history_limit

    def _get_history_snapshot_chronological(self) -> List[SimulationHistoryRecord]:
        """Return the entire history snapshot in chronological (oldest-first) order for reporting."""
        with self._lock:
            return list(self._history)

    def get_status(self) -> Dict[str, Any]:
        """
        Return a safe, read-only monitoring-state snapshot.

        The returned dictionary is the authoritative contract consumed by both
        the API route and the dashboard view model.

        Fields
        ------
        enabled : bool
            Whether the monitoring subsystem is active.  False until a real
            engine is introduced.
        state : str
            One of the :class:`MonitoringState` constants.
        state_display : str
            A human-readable label for *state* safe for display.
        last_successful_cycle : str or None
            ISO-8601 timestamp of the last completed monitoring cycle, or None.
        last_error_category : str or None
            A safe category string describing the last error, or None.
        health_summary : dict
            Minimal health summary from the AI health service.
        active_model_version : str or None
            Version string of the currently active model, or None if unconfigured.
        processed_flow_count : int
            Number of flows processed.  Zero until the monitoring engine runs.
        prediction_count : int
            Number of predictions generated.  Zero until the monitoring engine runs.
        alert_count : int
            Number of alerts generated.  Zero until the alert engine runs.
        updated_at : str or None
            ISO-8601 timestamp of when this status was last updated.  None when
            the monitoring engine has never run.
        note : str
            A human-readable note explaining the current state.
        """
        ai_health = self._get_ai_health_summary()
        active_version = self._get_active_model_version()


        with self._lock:
            state = self._state
            last_successful = self._last_successful_cycle
            last_err = self._last_error_category

            sim_cycle_count = self._simulation_cycle_count
            sim_flow_count = self._simulated_flow_count
            succ_inf_count = self._successful_simulation_inference_count
            fail_inf_count = self._failed_simulation_inference_count
            sim_rec_count = self._simulation_recommendation_count
            latest_res = self._latest_simulation_result

        updated_at = None
        if sim_cycle_count > 0:
            from utils.time_utils import get_current_utc_time
            updated_at = get_current_utc_time().isoformat()

        state_display = "Simulation Complete" if state == MonitoringState.SIMULATION_COMPLETE else state.title()
        if state_display == "Not_Configured":
            state_display = "Not Configured"

        return {
            "enabled": False,
            "state": state,
            "state_display": state_display,
            "last_successful_cycle": last_successful,
            "last_error_category": last_err,
            "health_summary": ai_health,
            "active_model_version": active_version,

            # Counters: zero is the honest initial value — not fabricated.
            "processed_flow_count": 0,
            "prediction_count": 0,
            "alert_count": 0,

            # Simulation specific metrics
            "simulation_cycle_count": sim_cycle_count,
            "simulated_flow_count": sim_flow_count,
            "successful_simulation_inference_count": succ_inf_count,
            "failed_simulation_inference_count": fail_inf_count,
            "simulation_recommendation_count": sim_rec_count,
            "latest_simulation_result": latest_res,

            "updated_at": updated_at,
            "note": (
                "Monitoring is not yet enabled. "
                "No live capture, inference, or alert generation is active."
            ),
        }
