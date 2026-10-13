import json
import logging
import os

from version import get_version


def log_event(logger, severity, event_category, **fields):
    payload = {
        "application_version": get_version(),
        "event_category": str(event_category)[:64],
        "process_id": os.getpid(),
    }
    allowed = {
        "request_id", "actor_public_id", "target_public_id", "outcome",
        "safe_error_category", "duration_ms",
    }
    for key, value in fields.items():
        if key in allowed and value is not None:
            payload[key] = value if isinstance(value, (int, float)) else str(value)[:128]
    logger.log(
        getattr(logging, str(severity).upper(), logging.INFO),
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
    )
