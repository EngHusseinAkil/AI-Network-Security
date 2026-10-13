"""
Centralized project version management and metadata.
"""
from typing import Dict, Any

MAJOR = 1
MINOR = 0
PATCH = 0

VERSION = f"{MAJOR}.{MINOR}.{PATCH}"
BUILD_DATE = "2026-07-27"
RELEASE_NAME = "Version 1.0.0"
API_VERSION = "v1"
DATABASE_SCHEMA_REVISION = "milestone_21_authentication"
SUPPORTED_DEPLOYMENT_MODES = ("development", "production", "testing")
GIT_COMMIT = None
PROCESS_LOCAL_LIMITATIONS = (
    "capture ownership and interface inventory",
    "packet metadata and flow histories",
    "live-flow evaluation history and counters",
)
PROJECT_NAME = "AI-Network-Security"
PROJECT_DESCRIPTION = "Enterprise-grade AI-powered network security platform."
AUTHOR = "AI-Network-Security Contributors"
LICENSE = "MIT"
REPOSITORY_URL = "https://github.com/placeholder/AI-Network-Security"
PYTHON_VERSION_MIN = "3.11"

def get_version() -> str:
    """Returns the current semantic version string."""
    return VERSION

def get_project_metadata() -> Dict[str, Any]:
    """Returns a dictionary containing all project metadata."""
    return {
        "project_name": PROJECT_NAME,
        "description": PROJECT_DESCRIPTION,
        "version": VERSION,
        "build_date": BUILD_DATE,
        "release_name": RELEASE_NAME,
        "api_version": API_VERSION,
        "database_schema_revision": DATABASE_SCHEMA_REVISION,
        "supported_deployment_modes": SUPPORTED_DEPLOYMENT_MODES,
        "git_commit": GIT_COMMIT,
        "process_local_limitations": PROCESS_LOCAL_LIMITATIONS,
        "author": AUTHOR,
        "license": LICENSE,
        "repository_url": REPOSITORY_URL,
        "python_version_min": PYTHON_VERSION_MIN
    }

def print_version_info() -> None:
    """Prints formatted project version and metadata to standard output."""
    print("=" * 40)
    print(f"Project: {PROJECT_NAME}")
    print(f"Version: {VERSION}")
    print(f"Build Date: {BUILD_DATE}")
    print(f"Author: {AUTHOR}")
    print(f"License: {LICENSE}")
    print("=" * 40)
