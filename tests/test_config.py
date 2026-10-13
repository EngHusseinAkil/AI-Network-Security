import os
import pytest
from config.environment import Environment
from config.settings import DevelopmentSettings, TestingSettings, ProductionSettings
from config.config import load_config

def test_load_config_development(monkeypatch):
    monkeypatch.setenv("APP_ENV", Environment.DEVELOPMENT.value)
    settings = load_config()
    assert isinstance(settings, DevelopmentSettings)
    assert settings.DEBUG is True

def test_load_config_testing(monkeypatch):
    monkeypatch.setenv("APP_ENV", Environment.TESTING.value)
    settings = load_config()
    assert isinstance(settings, TestingSettings)
    assert "memory" in settings.DATABASE_URI

def test_load_config_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", Environment.PRODUCTION.value)
    settings = load_config()
    assert isinstance(settings, ProductionSettings)
    assert settings.DEBUG is False

def test_load_config_invalid(monkeypatch):
    monkeypatch.setenv("APP_ENV", "invalid_env")
    with pytest.raises(ValueError, match="Invalid APP_ENV"):
        load_config()
