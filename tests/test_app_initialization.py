import subprocess
import sys
import os

def test_initialize_application_success():
    env = os.environ.copy()
    env["APP_ENV"] = "testing"
    result = subprocess.run([sys.executable, "app.py"], env=env, capture_output=True, text=True)
    assert result.returncode == 0
    assert "System is ready." in result.stdout

def test_initialize_application_failure():
    env = os.environ.copy()
    env["APP_ENV"] = "invalid_env"
    result = subprocess.run([sys.executable, "app.py"], env=env, capture_output=True, text=True)
    assert result.returncode == 1
    assert "Invalid APP_ENV" in result.stdout
