from version import get_version, get_project_metadata

def test_get_version():
    assert get_version() == "1.0.0"

def test_get_project_metadata():
    metadata = get_project_metadata()
    assert metadata["version"] == "1.0.0"
    assert metadata["api_version"] == "v1"
    assert metadata["database_schema_revision"] == "milestone_21_authentication"
    assert metadata["git_commit"] is None
    assert metadata["process_local_limitations"]
    assert metadata["project_name"] == "AI-Network-Security"
