"""
Version Service for the Backend API.
Extracts version metadata safely from project files.
"""
from typing import Dict, Any
from version import get_project_metadata

class VersionService:
    """Service to retrieve safe platform version metadata."""

    def __init__(self, api_version: str = "v1"):
        self.api_version = api_version

    def get_version_info(self) -> Dict[str, Any]:
        """Returns sanitized version metadata for the API contract."""
        metadata = get_project_metadata()

        return {
            "project_name": metadata.get("project_name", "AI-Network-Security"),
            "application_version": metadata.get("version", "unknown"),
            "api_version": self.api_version,
            "build_date": metadata.get("build_date"),
            "python_version_min": metadata.get("python_version_min")
            # Note: Model and schema versions are explicitly excluded here as per requirements.
        }
