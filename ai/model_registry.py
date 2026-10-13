"""
AI Model Registry.

Lightweight local registry to track available, compatible model artifacts,
enforce unique registration, and define the single active model safely.
"""

import os
import json
from typing import Dict, Any, List, Optional
from utils.exceptions import ValidationError

class ModelRegistry:
    def __init__(self, registry_file: str):
        """
        Initializes the model registry using a local JSON file.
        The registry file does not contain estimators, only metadata pointers.
        """
        self.registry_file = registry_file
        self._ensure_exists()

    def _ensure_exists(self):
        if not os.path.exists(self.registry_file):
            # Create parent dirs if necessary
            os.makedirs(os.path.dirname(os.path.abspath(self.registry_file)), exist_ok=True)
            self._save_state({
                "active_model_version": None,
                "registered_models": {}
            })

    def _load_state(self) -> Dict[str, Any]:
        with open(self.registry_file, "r") as f:
            return json.load(f)

    def _save_state(self, state: Dict[str, Any]):
        with open(self.registry_file, "w") as f:
            json.dump(state, f, indent=4)

    def register_model(self, model_version: str, model_dir: str, metadata: Dict[str, Any]):
        """
        Registers a new completed artifact.
        Fails if the version is already registered.
        """
        if not model_version or not model_dir:
            raise ValidationError("model_version and model_dir are required.")

        state = self._load_state()
        if model_version in state["registered_models"]:
            raise ValidationError(f"Model version '{model_version}' is already registered.")

        # We only save a shallow overview in the registry for fast lookups
        state["registered_models"][model_version] = {
            "model_dir": model_dir,
            "schema_version": metadata.get("schema_metadata", {}).get("schema_version"),
            "evaluated_row_count": metadata.get("model_metadata", {}).get("testing_row_count", 0),
            "is_testing_fallback_split": metadata.get("model_metadata", {}).get("stratification_status") == "disabled_testing_fallback"
        }

        self._save_state(state)

    def list_models(self) -> Dict[str, Any]:
        """Returns all registered models and their shallow metadata."""
        return self._load_state()["registered_models"]

    def get_active_model_version(self) -> Optional[str]:
        """Returns the version string of the currently active model."""
        return self._load_state().get("active_model_version")

    def activate_model(self, model_version: str):
        """
        Marks a specific model version as active.
        Must already be registered.
        Does NOT perform inference or network hook insertion.
        """
        state = self._load_state()
        if model_version not in state["registered_models"]:
            raise ValidationError(f"Cannot activate unknown model version '{model_version}'.")

        # Activation is simply a state pointer update
        state["active_model_version"] = model_version
        self._save_state(state)

    def deactivate_model(self):
        """Clears the active model pointer."""
        state = self._load_state()
        state["active_model_version"] = None
        self._save_state(state)
