"""
Directory Manager for the AI Network Security Platform.
Responsible for safely verifying and creating required project folders.
"""
from pathlib import Path
from typing import Dict, Any

from config import settings
from utils.logger import get_logger
from utils.exceptions import FileOperationError

logger = get_logger("DirectoryManager")

REQUIRED_DIRECTORIES = [
    "logs",
    "models",
    "data",
    "tests",
    "backend",
    "dashboard",
    "network",
    "config",
    "docs",
    "docs/design",
    "proposal"
]

def ensure_directory(path: Path | str) -> bool:
    """
    Ensures a single directory exists. Creates it if missing.
    Returns True if created, False if already existed.
    Raises FileOperationError on permission issues or serious failures.
    """
    dir_path = Path(path)
    if dir_path.exists():
        if not dir_path.is_dir():
            raise FileOperationError(
                f"Path exists but is not a directory: {dir_path}",
                details={"path": str(dir_path)}
            )
        return False

    try:
        dir_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created missing directory: {dir_path.name}")
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {dir_path}: {e}")
        raise FileOperationError(
            f"Failed to create directory: {e}",
            details={"path": str(dir_path)}
        )

def ensure_required_directories() -> None:
    """
    Iterates through all required project directories and ensures they exist.
    """
    logger.debug("Ensuring all required project directories exist...")
    base_dir = settings.BASE_DIR
    for dir_name in REQUIRED_DIRECTORIES:
        ensure_directory(base_dir / dir_name)

def verify_required_directories() -> bool:
    """
    Verifies if all required directories exist without attempting to create them.
    Returns True if all exist, False otherwise.
    """
    base_dir = settings.BASE_DIR
    for dir_name in REQUIRED_DIRECTORIES:
        if not (base_dir / dir_name).is_dir():
            return False
    return True

def get_directory_status_report() -> Dict[str, Any]:
    """
    Returns a structured status report of all required directories.
    """
    base_dir = settings.BASE_DIR
    report = {
        "status": "success",
        "missing_count": 0,
        "directories": {}
    }
    
    for dir_name in REQUIRED_DIRECTORIES:
        is_exists = (base_dir / dir_name).is_dir()
        report["directories"][dir_name] = "exists" if is_exists else "missing"
        if not is_exists:
            report["missing_count"] += 1
            report["status"] = "incomplete"
            
    return report
