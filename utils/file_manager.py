"""
Reusable file and directory helper functions.
"""
import json
from pathlib import Path
from typing import Any, Dict, Union

from utils.constants import DEFAULT_ENCODING

def ensure_directory_exists(directory_path: Union[str, Path]) -> None:
    """Safely creates a directory and its parents if they do not exist."""
    Path(directory_path).mkdir(parents=True, exist_ok=True)

def read_text_file(file_path: Union[str, Path]) -> str:
    """Reads a text file safely using UTF-8 encoding."""
    from utils.exceptions import FileOperationError
    path = Path(file_path)
    if not path.is_file():
        raise FileOperationError(f"File not found: {file_path}", details={"path": str(file_path)})
    try:
        return path.read_text(encoding=DEFAULT_ENCODING)
    except Exception as e:
        raise FileOperationError(f"Failed to read file: {e}", details={"path": str(file_path)})

def write_text_file(file_path: Union[str, Path], content: str, append: bool = False) -> None:
    """Writes text to a file safely using UTF-8 encoding."""
    path = Path(file_path)
    ensure_directory_exists(path.parent)
    mode = "a" if append else "w"
    with open(path, mode, encoding=DEFAULT_ENCODING) as f:
        f.write(content)

def read_json_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Reads a JSON file and parses it into a dictionary."""
    content = read_text_file(file_path)
    return json.loads(content)

def write_json_file(file_path: Union[str, Path], data: Dict[str, Any]) -> None:
    """Writes a dictionary to a JSON file safely."""
    path = Path(file_path)
    ensure_directory_exists(path.parent)
    with open(path, "w", encoding=DEFAULT_ENCODING) as f:
        json.dump(data, f, indent=4)
