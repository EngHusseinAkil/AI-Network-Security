"""
Tests for Controlled Scapy Capture Function.
Verifies capture limits, safe inputs, and mock behavior without live capture.
"""

import pytest
from unittest.mock import patch, MagicMock

from network.adapters.scapy_adapter import (
    is_scapy_available,
    capture_packets,
    validate_bpf_filter
)
from network.constants import DEFAULT_MAX_PACKET_SAMPLE_COUNT, DEFAULT_MAX_CAPTURE_DURATION_SECONDS


class MockIP: pass
class MockTCP: pass

@pytest.mark.skipif(not is_scapy_available(), reason="Scapy is not installed")
class TestScapyCapture:

    @pytest.fixture(autouse=True)
    def patch_scapy_layers(self):
        with patch("network.adapters.scapy_adapter._get_scapy_layers", return_value=(MockIP, MockTCP, MagicMock(), MagicMock())):
            yield
    
    def _create_mock_packet(self):
        """Creates a minimal mock IP packet."""
        mock_packet = MagicMock()
        mock_packet.time = 1.0
        mock_packet.__len__ = lambda s: 64
        
        def haslayer_side_effect(layer):
            return layer in [MockIP, MockTCP]
        mock_packet.haslayer.side_effect = haslayer_side_effect
        
        ip_layer = MagicMock(spec=MockIP)
        ip_layer.src = "192.168.1.10"
        ip_layer.dst = "8.8.8.8"
        ip_layer.ttl = 64
        
        tcp_layer = MagicMock(spec=MockTCP)
        tcp_layer.sport = 1234
        tcp_layer.dport = 80
        tcp_layer.flags = "S"
        
        def getitem_side_effect(layer):
            if layer == MockIP: return ip_layer
            if layer == MockTCP: return tcp_layer
            raise KeyError()
            
        mock_packet.__getitem__.side_effect = getitem_side_effect
        return mock_packet

    @patch("network.adapters.scapy_adapter._get_scapy_lib")
    def test_capture_packets_basic(self, mock_get_scapy_lib):
        """Verify sniff is called with basic args and translates output."""
        mock_scapy = MagicMock()
        mock_scapy.sniff.return_value = [self._create_mock_packet()]
        mock_get_scapy_lib.return_value = mock_scapy
        
        packets = capture_packets(packet_count=5, timeout=2)
        
        mock_scapy.sniff.assert_called_once_with(count=5, timeout=2, store=True)
        assert len(packets) == 1
        assert packets[0]["protocol"] == "TCP"
        assert packets[0]["source_ip"] == "192.168.1.10"

    @patch("network.adapters.scapy_adapter._get_scapy_lib")
    def test_capture_packets_bounds_enforcement(self, mock_get_scapy_lib):
        """Verify sniff count and timeout limits are enforced."""
        mock_scapy = MagicMock()
        mock_scapy.sniff.return_value = []
        mock_get_scapy_lib.return_value = mock_scapy
        
        # Request way over bounds
        capture_packets(
            packet_count=DEFAULT_MAX_PACKET_SAMPLE_COUNT + 1000, 
            timeout=DEFAULT_MAX_CAPTURE_DURATION_SECONDS + 1000
        )
        
        mock_scapy.sniff.assert_called_once_with(
            count=DEFAULT_MAX_PACKET_SAMPLE_COUNT,
            timeout=DEFAULT_MAX_CAPTURE_DURATION_SECONDS,
            store=True
        )

    def test_capture_invalid_interface(self):
        """Verify invalid interfaces are rejected safely."""
        with pytest.raises(ValueError, match="Invalid interface name"):
            capture_packets(interface_name="eth0;")
            
    def test_capture_invalid_filter(self):
        """Verify malicious filters are rejected safely."""
        with pytest.raises(ValueError, match="Invalid BPF filter"):
            capture_packets(packet_filter="tcp port 80; rm -rf /")
            
    def test_validate_bpf_filter(self):
        """Verify BPF filter validator stringent rules."""
        assert validate_bpf_filter("tcp port 80") is True
        assert validate_bpf_filter("host 192.168.1.1") is True
        assert validate_bpf_filter(None) is True
        
        assert validate_bpf_filter("port 80;") is False
        assert validate_bpf_filter("host 1.1.1.1 & echo") is False
        assert validate_bpf_filter("tcp | bash") is False

    @patch("network.adapters.scapy_adapter._get_scapy_lib")
    def test_capture_permission_error(self, mock_get_scapy_lib):
        """Verify permission errors are caught and return empty list."""
        mock_scapy = MagicMock()
        mock_scapy.sniff.side_effect = PermissionError("Access denied")
        mock_get_scapy_lib.return_value = mock_scapy
        
        packets = capture_packets()
        assert packets == []
        
    @patch("network.adapters.scapy_adapter._get_scapy_lib")
    def test_capture_os_error(self, mock_get_scapy_lib):
        """Verify OS errors (like missing Npcap) are caught safely."""
        mock_scapy = MagicMock()
        mock_scapy.sniff.side_effect = OSError("Npcap not installed")
        mock_get_scapy_lib.return_value = mock_scapy
        
        packets = capture_packets()
        assert packets == []

    @patch("network.adapters.scapy_adapter._check_scapy_installed", return_value=False)
    def test_capture_scapy_unavailable(self, mock_installed):
        """Verify graceful degradation when scapy is missing."""
        packets = capture_packets()
        assert packets == []
