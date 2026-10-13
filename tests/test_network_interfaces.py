"""
Tests for Interface Discovery Abstraction.
Ensures safe MAC masking, synthetic injection, and invalid name handling.
"""

import pytest

from network.metadata import InterfaceMetadata
from network.interfaces import (
    enable_synthetic_mode,
    disable_synthetic_mode,
    mask_mac_address,
    list_interfaces,
    get_active_interfaces,
    get_interface_by_name,
    validate_interface_name
)


@pytest.fixture(autouse=True)
def setup_and_teardown_synthetic_mode():
    """Ensure synthetic mode is disabled before and after each test."""
    disable_synthetic_mode()
    yield
    disable_synthetic_mode()


def test_mask_mac_address():
    """Verify MAC addresses are safely masked."""
    assert mask_mac_address("00:1A:2B:3C:4D:5E") == "00:1A:2B:**:**:**"
    assert mask_mac_address("00-1A-2B-3C-4D-5E") == "00-1A-2B-**-**-**"
    
    # Invalid/Short MACs should be returned as is (or handled safely without crashing)
    assert mask_mac_address("invalid_mac") == "invalid_mac"
    assert mask_mac_address(None) is None


def test_synthetic_interface_injection():
    """Verify we can inject and retrieve synthetic interfaces safely."""
    mock_interfaces = [
        InterfaceMetadata("eth0", "Mock Eth", True, "11:22:33:44:55:66", ["10.0.0.1"]),
        InterfaceMetadata("wlan0", "Mock Wlan", False, "AA:BB:CC:DD:EE:FF", [])
    ]
    
    enable_synthetic_mode(mock_interfaces)
    
    interfaces = list_interfaces()
    assert len(interfaces) == 2
    assert interfaces[0].name == "eth0"
    
    # Verify the MAC was masked during retrieval!
    assert interfaces[0].mac_address == "11:22:33:**:**:**"
    assert interfaces[1].mac_address == "AA:BB:CC:**:**:**"


def test_get_active_interfaces():
    """Verify filtering of interfaces that are UP."""
    mock_interfaces = [
        InterfaceMetadata("eth0", "UP Interface", True, "11:22:33:44:55:66", ["10.0.0.1"]),
        InterfaceMetadata("wlan0", "DOWN Interface", False, "AA:BB:CC:DD:EE:FF", [])
    ]
    enable_synthetic_mode(mock_interfaces)
    
    active = get_active_interfaces()
    assert len(active) == 1
    assert active[0].name == "eth0"


def test_validate_interface_name():
    """Verify malicious/invalid interface names are rejected."""
    assert validate_interface_name("eth0") is True
    assert validate_interface_name("Wi-Fi") is True
    assert validate_interface_name("Local Area Connection") is True
    
    # Malicious inputs
    assert validate_interface_name("eth0;") is False
    assert validate_interface_name("eth0 && rm -rf /") is False
    assert validate_interface_name("../../etc/passwd") is False
    assert validate_interface_name("eth0|bash") is False
    assert validate_interface_name("") is False
    assert validate_interface_name(None) is False


def test_get_interface_by_name():
    """Verify we can lookup an interface by name."""
    mock_interfaces = [
        InterfaceMetadata("eth0", "UP Interface", True, "11:22:33:44:55:66", ["10.0.0.1"]),
        InterfaceMetadata("wlan0", "DOWN Interface", False, "AA:BB:CC:DD:EE:FF", [])
    ]
    enable_synthetic_mode(mock_interfaces)
    
    iface = get_interface_by_name("wlan0")
    assert iface is not None
    assert iface.name == "wlan0"
    assert iface.is_up is False
    
    # Non-existent
    assert get_interface_by_name("eth1") is None
    
    # Invalid name
    with pytest.raises(ValueError):
        get_interface_by_name("eth0;")


def test_real_interface_fallback():
    """
    Verify the fallback real interface logic works without crashing.
    This doesn't check specific values since it relies on the host OS,
    but it ensures the function returns a valid InterfaceMetadata list.
    """
    interfaces = list_interfaces()
    assert len(interfaces) >= 1
    assert isinstance(interfaces[0], InterfaceMetadata)
    assert interfaces[0].name in ["lo0", "eth0"]
    assert "**:**:**" in interfaces[0].mac_address
