from datetime import datetime, timezone
from utils.time_utils import get_current_utc_time, get_current_local_time, format_datetime, parse_datetime, generate_log_safe_timestamp

def test_get_current_utc_time():
    dt = get_current_utc_time()
    assert dt.tzinfo == timezone.utc

def test_format_and_parse():
    dt = datetime(2026, 7, 6, 12, 0, 0)
    formatted = format_datetime(dt)
    parsed = parse_datetime(formatted)
    assert dt == parsed

def test_generate_log_safe_timestamp():
    stamp = generate_log_safe_timestamp()
    assert "_" in stamp
    assert len(stamp) == 15  # YYYYMMDD_HHMMSS
