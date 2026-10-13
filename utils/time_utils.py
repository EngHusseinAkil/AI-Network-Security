"""
Reusable time and date helpers.
"""
from datetime import datetime, timezone
from utils.constants import DATETIME_FORMAT, LOG_SAFE_DATETIME_FORMAT

def get_current_utc_time() -> datetime:
    """Returns the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)

def get_current_local_time() -> datetime:
    """Returns the current local timezone-aware datetime."""
    return datetime.now().astimezone()

def format_datetime(dt: datetime, format_string: str = DATETIME_FORMAT) -> str:
    """Formats a datetime object to a string."""
    return dt.strftime(format_string)

def parse_datetime(dt_string: str, format_string: str = DATETIME_FORMAT) -> datetime:
    """Parses a datetime string back into a datetime object."""
    return datetime.strptime(dt_string, format_string)

def generate_log_safe_timestamp() -> str:
    """Generates a file-safe timestamp string for logs and files."""
    return get_current_utc_time().strftime(LOG_SAFE_DATETIME_FORMAT)
