"""
Generic validation helpers for strings, paths, and simple data structures.
"""
from typing import Any, Dict
from pathlib import Path

def validate_string(value: Any, min_length: int = 1) -> bool:
    """Validates that a value is a string and meets a minimum length."""
    if not isinstance(value, str):
        return False
    return len(value.strip()) >= min_length

def validate_path_exists(path: Path | str) -> bool:
    """Validates that a given file or directory path exists."""
    return Path(path).exists()

def validate_port(port: Any) -> bool:
    """Validates that a value is a valid network port number (1-65535)."""
    try:
        port_int = int(port)
        return 0 < port_int <= 65535
    except (ValueError, TypeError):
        return False

def validate_dictionary_keys(data: Dict[str, Any], required_keys: list[str]) -> bool:
    """Validates that a dictionary contains all required keys."""
    if not isinstance(data, dict):
        return False
    return all(key in data for key in required_keys)
