import subprocess
import sys
import pytest


@pytest.mark.parametrize("module", [
    "network.capture_models", "network.capture_config", "network.packet_source",
    "network.fake_source", "network.interfaces", "network.capture_service",
    "backend.dependencies",
])
def test_import_does_not_load_scapy(module):
    code = f"import {module}; import sys; assert not any(x == 'scapy' or x.startswith('scapy.') for x in sys.modules)"
    subprocess.run([sys.executable, "-c", code], check=True)


def test_create_app_does_not_load_scapy():
    code = ("from backend.app_factory import create_app; create_app({'TESTING': True}); "
            "import sys; assert not any(x == 'scapy' or x.startswith('scapy.') for x in sys.modules)")
    subprocess.run([sys.executable, "-c", code], check=True)
