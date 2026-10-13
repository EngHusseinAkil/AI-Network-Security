import pytest
from pathlib import Path
from utils.file_manager import ensure_directory_exists, write_text_file, read_text_file, write_json_file, read_json_file
from utils.exceptions import FileOperationError

def test_file_manager_text(tmp_path):
    file_path = tmp_path / "test.txt"
    write_text_file(file_path, "hello")
    content = read_text_file(file_path)
    assert content == "hello"

def test_file_manager_json(tmp_path):
    file_path = tmp_path / "test.json"
    data = {"key": "value"}
    write_json_file(file_path, data)
    loaded = read_json_file(file_path)
    assert loaded == data

def test_read_nonexistent_file():
    with pytest.raises(FileOperationError):
        read_text_file("does_not_exist_ever_999.txt")
