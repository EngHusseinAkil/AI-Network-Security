from pathlib import Path

from version import VERSION, get_project_metadata


ROOT = Path(__file__).resolve().parent.parent


def test_authoritative_release_version_locations_agree():
    assert VERSION == "1.0.0"
    assert get_project_metadata()["version"] == VERSION
    assert "org.opencontainers.image.version=\"1.0.0\"" in (
        ROOT / "Dockerfile"
    ).read_text(encoding="utf-8")
    assert "AI Network Security 1.0.0" in (
        ROOT / "README.md"
    ).read_text(encoding="utf-8")
    assert "## [1.0.0] - 2026-07-27" in (
        ROOT / "CHANGELOG.md"
    ).read_text(encoding="utf-8")
    assert "# AI Network Security 1.0.0" in (
        ROOT / "docs" / "RELEASE_NOTES_1.0.0.md"
    ).read_text(encoding="utf-8")


def test_release_document_inventory_is_complete():
    required = {
        "ADMINISTRATOR_GUIDE.md",
        "API_REFERENCE.md",
        "ARCHITECTURE.md",
        "BACKUP_RESTORE_DRILL_1.0.0.md",
        "DEMO_GUIDE.md",
        "FINAL_PROJECT_REPORT.md",
        "MIGRATION_VERIFICATION_1.0.0.md",
        "MODEL_EVALUATION_SUMMARY.md",
        "PERFORMANCE_BASELINE_1.0.0.md",
        "RELEASE_CHECKLIST_1.0.0.md",
        "RELEASE_NOTES_1.0.0.md",
        "RELEASE_TEST_MATRIX_1.0.0.md",
        "THREAT_MODEL.md",
        "USER_GUIDE.md",
    }
    assert required <= {path.name for path in (ROOT / "docs").glob("*.md")}
