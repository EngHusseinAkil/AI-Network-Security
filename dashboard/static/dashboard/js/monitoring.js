/**
 * monitoring.js — Safe, bounded browser polling for the monitoring status page.
 *
 * Design constraints (Phase 6 – Milestone 7)
 * ------------------------------------------
 * * Only runs on the monitoring page (guarded by panel element presence).
 * * Only polls GET /api/v1/monitoring/status — no other endpoints.
 * * No external libraries; plain fetch() only.
 * * Configurable interval, read from data-* attributes on the panel element.
 * * Minimum interval floor enforced (at least poll_min_interval_ms).
 * * One request in flight at a time — overlapping requests are prevented.
 * * Exponential backoff after failures, capped at poll_max_backoff_ms.
 * * Polling pauses when the page/tab becomes hidden; resumes when visible.
 * * DOM updates use textContent only — never innerHTML with server data.
 * * State values are mapped through an allowlist before becoming CSS classes.
 * * Raw error bodies are never rendered; only safe static messages are shown.
 * * No crash on malformed JSON or unexpected field shapes.
 * * The request is aborted if it exceeds a reasonable timeout.
 * * Polling stops cleanly if the panel element is removed from the DOM.
 */

(function monitoringPoller() {
    "use strict";

    // -----------------------------------------------------------------------
    // Guard: only activate on pages that have the monitoring panel
    // -----------------------------------------------------------------------
    const panel = document.getElementById("monitoring-status-panel");
    if (!panel) {
        // Not the monitoring page — do nothing.
        return;
    }

    // -----------------------------------------------------------------------
    // Configuration (read from data-* attributes, with safe fallbacks)
    // -----------------------------------------------------------------------
    const ENDPOINT        = panel.dataset.pollEndpoint    || "/api/v1/monitoring/status";
    const INTERVAL_MS     = Math.max(
        parseInt(panel.dataset.pollMinInterval || "5000", 10),
        parseInt(panel.dataset.pollInterval    || "15000", 10)
    );
    const MIN_INTERVAL_MS = Math.max(5000,  parseInt(panel.dataset.pollMinInterval || "5000",   10));
    const MAX_BACKOFF_MS  = Math.min(120000, parseInt(panel.dataset.pollMaxBackoff  || "120000", 10));
    const FETCH_TIMEOUT_MS = 10000; // 10 s — not configurable from template

    // -----------------------------------------------------------------------
    // Allowlisted state → CSS badge class mapping
    // Only values in this map ever become class names on DOM nodes.
    // -----------------------------------------------------------------------
    const STATE_BADGE = Object.freeze({
        "disabled":       "info",
        "idle":           "info",
        "starting":       "warning",
        "running":        "success",
        "degraded":       "warning",
        "stopped":        "info",
        "error":          "danger",
        "not_configured": "info",
        "unknown":        "info",
    });

    const STATE_DISPLAY = Object.freeze({
        "disabled":       "Disabled",
        "idle":           "Idle",
        "starting":       "Starting",
        "running":        "Running",
        "degraded":       "Degraded",
        "stopped":        "Stopped",
        "error":          "Error",
        "not_configured": "Not Configured",
        "unknown":        "Unknown",
    });

    function safeBadgeClass(state) {
        return STATE_BADGE[state] || "info";
    }

    function safeDisplay(state) {
        return STATE_DISPLAY[state] || "Unknown";
    }

    // -----------------------------------------------------------------------
    // DOM helpers — textContent only, never innerHTML
    // -----------------------------------------------------------------------

    function setText(id, value) {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = (value !== null && value !== undefined && value !== "")
                ? String(value)
                : "—";
        }
    }

    function setStatus(id, value, fallback) {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = (value !== null && value !== undefined && String(value).trim() !== "")
                ? String(value)
                : fallback;
        }
    }

    function setPollNotice(message) {
        const el = document.getElementById("monitoring-poll-notice");
        if (el) el.textContent = message;
    }

    function setPollStatusBar(message, visible) {
        const bar = document.getElementById("monitoring-poll-status");
        if (!bar) return;
        bar.textContent = message; // textContent only
        if (visible) {
            bar.removeAttribute("hidden");
        } else {
            bar.setAttribute("hidden", "");
        }
    }

    function applyStateBadge(state) {
        const badge = document.getElementById("monitoring-state-badge");
        if (!badge) return;

        // Remove any existing badge-* classes
        Array.from(badge.classList)
            .filter(cls => cls.startsWith("badge-"))
            .forEach(cls => badge.classList.remove(cls));

        badge.classList.add("badge-" + safeBadgeClass(state));

        const textEl = document.getElementById("monitoring-state-text");
        if (textEl) textEl.textContent = safeDisplay(state);
    }

    // -----------------------------------------------------------------------
    // Update DOM from a successfully parsed status payload
    // -----------------------------------------------------------------------

    function applyStatus(data) {
        // data is the "data" sub-object from the API envelope
        const state = (typeof data.state === "string") ? data.state : "unknown";
        applyStateBadge(state);

        const enabledText = data.enabled === true ? "Enabled" : "Disabled";
        setText("monitoring-enabled-text", enabledText);
        setText("monitoring-note-text", data.note);

        // Model version
        setText("mon-model-version", data.active_model_version);

        // Health summary
        const hs = (typeof data.health_summary === "object" && data.health_summary !== null)
            ? data.health_summary : {};
        setText("mon-health-status",  hs.overall_status);
        setText("mon-readiness",      hs.readiness_level);

        // Counters — only integers, fallback to "0" on bad input
        const flowCount = Number.isInteger(data.processed_flow_count) ? data.processed_flow_count : 0;
        const predCount = Number.isInteger(data.prediction_count)     ? data.prediction_count     : 0;
        const alrtCount = Number.isInteger(data.alert_count)          ? data.alert_count          : 0;
        setText("mon-flow-count",  flowCount);
        setText("mon-pred-count",  predCount);
        setText("mon-alert-count", alrtCount);

        // Timestamps
        setText("mon-last-cycle", data.last_successful_cycle);
        setStatus("mon-last-error", data.last_error_category, "None");
        setText("mon-updated-at",  data.updated_at);
    }

    // -----------------------------------------------------------------------
    // Polling engine
    // -----------------------------------------------------------------------

    let inFlight    = false;   // true while a fetch is pending
    let timerId     = null;    // handle for the next scheduled poll
    let backoffMs   = 0;       // current additional backoff duration
    let failCount   = 0;       // consecutive failure counter

    function scheduleNext(delayMs) {
        if (timerId !== null) {
            clearTimeout(timerId);
        }
        timerId = setTimeout(poll, delayMs);
    }

    function onSuccess() {
        failCount = 0;
        backoffMs = 0;
        setPollStatusBar("", false); // hide error bar on success
        scheduleNext(INTERVAL_MS);
    }

    function onFailure(reason) {
        failCount += 1;

        // Exponential backoff: 2^failCount seconds, capped at MAX_BACKOFF_MS.
        // We use a simple doubling strategy with a minimum of INTERVAL_MS.
        const rawBackoff = Math.min(
            MAX_BACKOFF_MS,
            INTERVAL_MS * Math.pow(2, failCount)
        );
        backoffMs = rawBackoff;

        // Safe static degraded message — no server content exposed.
        setPollStatusBar(
            "Status unavailable. Retrying in " + Math.round(backoffMs / 1000) + " s.",
            true
        );

        // Apply degraded visual state
        applyStateBadge("unknown");

        scheduleNext(Math.max(MIN_INTERVAL_MS, backoffMs));
    }

    async function poll() {
        // Bail if panel was removed from DOM (page navigated away)
        if (!document.getElementById("monitoring-status-panel")) {
            return;
        }
        // One request at a time — skip if another is still in flight
        if (inFlight) {
            scheduleNext(INTERVAL_MS);
            return;
        }

        inFlight = true;
        const controller = new AbortController();
        const timeoutId  = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

        try {
            const response = await fetch(ENDPOINT, {
                method:  "GET",
                headers: { "Accept": "application/json" },
                signal:  controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // Non-2xx response (e.g. 503): degrade safely, no body rendered.
                onFailure("http-" + response.status);
                return;
            }

            let json;
            try {
                json = await response.json();
            } catch (_parseError) {
                // Malformed JSON — degrade safely.
                onFailure("parse-error");
                return;
            }

            // Validate envelope shape: must have "data" key
            if (typeof json !== "object" || json === null || !("data" in json)) {
                onFailure("envelope-missing");
                return;
            }

            const data = json.data;
            if (typeof data !== "object" || data === null) {
                onFailure("data-invalid");
                return;
            }

            // Update DOM with validated data
            applyStatus(data);
            onSuccess();

        } catch (err) {
            clearTimeout(timeoutId);
            // Network error or abort (timeout) — degrade safely.
            onFailure(err.name === "AbortError" ? "timeout" : "network-error");
        } finally {
            inFlight = false;
        }
    }

    // -----------------------------------------------------------------------
    // Page Visibility API — pause when hidden, resume when visible
    // -----------------------------------------------------------------------

    function onVisibilityChange() {
        if (document.hidden) {
            // Page tab is hidden — cancel pending poll to avoid wasted requests.
            if (timerId !== null) {
                clearTimeout(timerId);
                timerId = null;
            }
            setPollNotice("Polling paused (page hidden). Will resume when visible.");
        } else {
            // Tab became visible again — resume polling immediately.
            setPollNotice(
                "Live status polling active. Updates every " +
                Math.round(INTERVAL_MS / 1000) + " s."
            );
            scheduleNext(0); // immediate poll on resume
        }
    }

    document.addEventListener("visibilitychange", onVisibilityChange);

    // -----------------------------------------------------------------------
    // Start polling
    // -----------------------------------------------------------------------

    setPollNotice(
        "Live status polling active. Updates every " +
        Math.round(INTERVAL_MS / 1000) + " s."
    );

    // First poll after a short delay to allow the page to render fully.
    scheduleNext(500);

}());

(function deviceSelectionControls() {
    "use strict";
    const checkboxes = () => Array.from(document.querySelectorAll(
        'input[name="selected_device_ip"]'
    ));
    const all = document.querySelector("[data-device-select-all]");
    const clear = document.querySelector("[data-device-clear-all]");
    if (all) all.addEventListener("click", () => checkboxes().forEach(item => { item.checked = true; }));
    if (clear) clear.addEventListener("click", () => checkboxes().forEach(item => { item.checked = false; }));
}());

(function simulationPresetControl() {
    "use strict";
    const button = document.querySelector("[data-simulation-preset]");
    if (!button) return;
    button.addEventListener("click", () => {
        let preset;
        try { preset = JSON.parse(button.dataset.simulationPreset); } catch (_) { return; }
        Object.keys(preset).forEach((name) => {
            const input = document.querySelector(`.simulation-form [name="${name}"]`);
            if (input) input.value = preset[name];
        });
    });
}());
