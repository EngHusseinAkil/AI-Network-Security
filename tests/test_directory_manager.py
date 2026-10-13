from pathlib import Path
from utils.directory_manager import ensure_directory, verify_required_directories, get_directory_status_report

def test_ensure_directory(tmp_path):
    new_dir = tmp_path / "new_dir"
    assert ensure_directory(new_dir) is True
    assert new_dir.is_dir()
    assert ensure_directory(new_dir) is False

def test_verify_required_directories():
    # In the current project state, they should all exist
    assert verify_required_directories() is True

def test_get_directory_status_report():
    report = get_directory_status_report()
    assert "status" in report
    assert "missing_count" in report
    assert "directories" in report
