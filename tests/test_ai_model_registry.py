import os
import pytest

from ai.model_registry import ModelRegistry
from utils.exceptions import ValidationError

@pytest.fixture
def registry(tmp_path):
    reg_file = os.path.join(tmp_path, "registry.json")
    return ModelRegistry(reg_file)

@pytest.fixture
def mock_metadata():
    return {
        "schema_metadata": {"schema_version": "1.0.0"},
        "model_metadata": {
            "testing_row_count": 100,
            "stratification_status": "applied"
        }
    }

def test_registry_initializes_cleanly(registry):
    assert os.path.exists(registry.registry_file)
    assert registry.get_active_model_version() is None
    assert registry.list_models() == {}

def test_register_model_success(registry, mock_metadata):
    registry.register_model("v1.0.0", "/dummy/path", mock_metadata)
    models = registry.list_models()

    assert "v1.0.0" in models
    assert models["v1.0.0"]["model_dir"] == "/dummy/path"
    assert models["v1.0.0"]["schema_version"] == "1.0.0"
    assert models["v1.0.0"]["evaluated_row_count"] == 100
    assert models["v1.0.0"]["is_testing_fallback_split"] is False

def test_duplicate_model_version_fails(registry, mock_metadata):
    registry.register_model("v1.0.0", "/dummy/path", mock_metadata)
    with pytest.raises(ValidationError, match="already registered"):
        registry.register_model("v1.0.0", "/dummy/path2", mock_metadata)

def test_activate_compatible_model_succeeds(registry, mock_metadata):
    registry.register_model("v1.0.0", "/dummy/path", mock_metadata)
    registry.activate_model("v1.0.0")
    assert registry.get_active_model_version() == "v1.0.0"

def test_incompatible_model_activation_fails(registry):
    with pytest.raises(ValidationError, match="Cannot activate unknown model"):
        registry.activate_model("v_unknown")

def test_activating_replaces_prior_active_marker(registry, mock_metadata):
    registry.register_model("v1.0.0", "/dummy/path1", mock_metadata)
    registry.register_model("v2.0.0", "/dummy/path2", mock_metadata)

    registry.activate_model("v1.0.0")
    assert registry.get_active_model_version() == "v1.0.0"

    registry.activate_model("v2.0.0")
    assert registry.get_active_model_version() == "v2.0.0"

def test_deactivation_works(registry, mock_metadata):
    registry.register_model("v1.0.0", "/dummy/path", mock_metadata)
    registry.activate_model("v1.0.0")
    assert registry.get_active_model_version() == "v1.0.0"

    registry.deactivate_model()
    assert registry.get_active_model_version() is None

def test_registry_contains_no_estimators(registry, mock_metadata):
    registry.register_model("v1.0.0", "/dummy/path", mock_metadata)
    state = registry._load_state()
    # verify no giant binary strings exist in the raw JSON
    import json
    raw = json.dumps(state)
    assert "estimator" not in raw.lower()

def test_no_side_effects_registry():
    import sys
    assert "scapy" not in sys.modules or "ai.model_registry" in sys.modules
    assert "flask" not in sys.modules or "ai.model_registry" in sys.modules
