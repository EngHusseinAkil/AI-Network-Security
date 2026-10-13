"""
Tests for Scapy Adapter.
Verifies conversion of Scapy-like packet objects into safe metadata dictionaries.
Does not require live capture or Npcap.
"""

import pytest
from unittest.mock import MagicMock, patch

from network.adapters.scapy_adapter import (
    ScapyPacketSource, extract_scapy_metadata, is_scapy_available,
)
from network.capture_config import CaptureConfig
from network.parser import parse_packet


class MockIP: pass
class MockTCP: pass
class MockUDP: pass
class MockICMP: pass
class MockARP: pass
class MockIPv6: pass

# We only run adapter logic tests if scapy installed, but our environment should have it
@pytest.mark.skipif(not is_scapy_available(), reason="Scapy is not installed")
class TestScapyAdapter:
    
    @pytest.fixture(autouse=True)
    def patch_scapy_layers(self):
        with patch("network.adapters.scapy_adapter._get_scapy_layers", return_value=(MockIP, MockTCP, MockUDP, MockICMP)):
            yield

    def _create_mock_ip_layer(self):
        """Creates a mock Scapy IP layer."""
        ip_layer = MagicMock(spec=MockIP)
        ip_layer.src = "192.168.1.50"
        ip_layer.dst = "8.8.8.8"
        ip_layer.ttl = 64
        return ip_layer

    def test_scapy_availability(self):
        """Verify Scapy availability check works."""
        assert is_scapy_available() is True

    def test_extract_tcp_packet(self):
        """Verify extraction of TCP packet."""
        mock_packet = MagicMock()
        mock_packet.time = 1600000000.0
        mock_packet.__len__ = lambda s: 1500
        
        def haslayer_side_effect(layer):
            return layer in [MockIP, MockTCP]
        mock_packet.haslayer.side_effect = haslayer_side_effect
        
        ip_layer = self._create_mock_ip_layer()
        tcp_layer = MagicMock(spec=MockTCP)
        tcp_layer.sport = 12345
        tcp_layer.dport = 443
        tcp_layer.flags = "SA"  # SYN-ACK
        
        def getitem_side_effect(layer):
            if layer == MockIP: return ip_layer
            if layer == MockTCP: return tcp_layer
            raise KeyError()
        mock_packet.__getitem__.side_effect = getitem_side_effect

        packet_dict = extract_scapy_metadata(mock_packet, "eth0")
        
        assert packet_dict is not None
        assert packet_dict["protocol"] == "TCP"
        assert packet_dict["source_ip"] == "192.168.1.50"
        assert packet_dict["source_port"] == 12345
        assert packet_dict["packet_size"] == 1500
        assert packet_dict["tcp_flags"] == "S,A"
        assert "payload" not in packet_dict
        
        # Verify parser compatibility
        meta = parse_packet(packet_dict)
        assert meta.protocol == "TCP"

    def test_extract_udp_packet(self):
        """Verify extraction of UDP packet."""
        mock_packet = MagicMock()
        mock_packet.time = 1600000000.0
        mock_packet.__len__ = lambda s: 500
        
        def haslayer_side_effect(layer):
            return layer in [MockIP, MockUDP]
        mock_packet.haslayer.side_effect = haslayer_side_effect
        
        ip_layer = self._create_mock_ip_layer()
        udp_layer = MagicMock(spec=MockUDP)
        udp_layer.sport = 53
        udp_layer.dport = 12345
        
        def getitem_side_effect(layer):
            if layer == MockIP: return ip_layer
            if layer == MockUDP: return udp_layer
            raise KeyError()
        mock_packet.__getitem__.side_effect = getitem_side_effect

        packet_dict = extract_scapy_metadata(mock_packet)
        
        assert packet_dict is not None
        assert packet_dict["protocol"] == "UDP"
        assert packet_dict["destination_port"] == 12345
        assert "tcp_flags" not in packet_dict
        
        meta = parse_packet(packet_dict)
        assert meta.protocol == "UDP"

    def test_extract_icmp_packet(self):
        """Verify extraction of ICMP packet."""
        mock_packet = MagicMock()
        mock_packet.time = 1600000000.0
        mock_packet.__len__ = lambda s: 64
        
        def haslayer_side_effect(layer):
            return layer in [MockIP, MockICMP]
        mock_packet.haslayer.side_effect = haslayer_side_effect
        
        ip_layer = self._create_mock_ip_layer()
        
        def getitem_side_effect(layer):
            if layer == MockIP: return ip_layer
            raise KeyError()
        mock_packet.__getitem__.side_effect = getitem_side_effect

        packet_dict = extract_scapy_metadata(mock_packet)
        
        assert packet_dict is not None
        assert packet_dict["protocol"] == "ICMP"
        assert "source_port" not in packet_dict
        
        meta = parse_packet(packet_dict)
        assert meta.protocol == "ICMP"

    def test_unsupported_non_ip_packet(self):
        """Verify adapter rejects/ignores non-IP packets (e.g. ARP/STP)."""
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False  # No IP layer
        
        packet_dict = extract_scapy_metadata(mock_packet)
        assert packet_dict is None

    def test_payload_exclusion_guarantee(self):
        """Ensure no payloads are extracted from Scapy objects."""
        mock_packet = MagicMock()
        mock_packet.haslayer.side_effect = lambda l: l in [MockIP, MockTCP]
        
        ip_layer = self._create_mock_ip_layer()
        tcp_layer = MagicMock(spec=MockTCP)
        tcp_layer.sport = 80
        tcp_layer.dport = 12345
        tcp_layer.flags = "A"
        
        # Scapy packets have a payload property, we make sure it's not extracted
        mock_packet.payload = "EVIL_PAYLOAD_BYTES"
        
        mock_packet.__getitem__.side_effect = lambda l: ip_layer if l == MockIP else tcp_layer
        mock_packet.__len__ = lambda s: 100
        mock_packet.time = 1.0

        packet_dict = extract_scapy_metadata(mock_packet)
        
        assert "payload" not in packet_dict
        assert "EVIL_PAYLOAD_BYTES" not in str(packet_dict)


@pytest.mark.skipif(not is_scapy_available(), reason="Scapy is not installed")
class TestScapyLivePacketSource:

    @pytest.fixture(autouse=True)
    def patch_scapy(self):
        with patch("network.adapters.scapy_adapter._get_scapy_layers",
                   return_value=(MockIP, MockTCP, MockUDP, MockICMP)) as layers:
            self.layers = layers
            yield

    @staticmethod
    def packet(*layers, length=64, layer_map=None):
        packet = MagicMock()
        packet.time = 1600000000.0
        packet.__len__ = lambda s: length
        packet.src = packet.dst = None
        layer_map = layer_map or {}
        packet.haslayer.side_effect = lambda layer: layer in layer_map
        packet.__getitem__.side_effect = layer_map.__getitem__
        return packet

    @staticmethod
    def ip_packet(transport_type, transport):
        ip = MagicMock(spec=MockIP)
        ip.src, ip.dst = "192.168.137.10", "8.8.8.8"
        ip.ttl = 64
        return TestScapyLivePacketSource.packet(
            ip, transport, layer_map={MockIP: ip, transport_type: transport}
        )

    def read(self, packet):
        source = ScapyPacketSource("wifi", "192.168.137.0/24")
        config = CaptureConfig(enabled=True)
        with patch("network.adapters.scapy_adapter._get_scapy_lib") as scapy:
            scapy.return_value.sniff.return_value = [packet]
            source.open("native-wifi", config)
            return source.read_metadata(1)

    def test_arp_frame_is_skipped_safely(self):
        assert self.read(self.packet(MockARP(), layer_map={})) is None

    def test_ipv6_frame_is_skipped_when_ipv6_is_unsupported(self):
        assert self.read(self.packet(MockIPv6(), layer_map={})) is None

    @pytest.mark.parametrize("transport, protocol", [
        (MockTCP, "TCP"), (MockUDP, "UDP"), (MockICMP, "ICMP"),
    ])
    def test_ipv4_protocol_metadata_and_direction_are_preserved(self, transport, protocol):
        layer = MagicMock(spec=transport)
        if transport is MockTCP or transport is MockUDP:
            layer.sport, layer.dport = 1234, 443
        if transport is MockTCP:
            layer.flags = "S"
        metadata = self.read(self.ip_packet(transport, layer))
        assert metadata.protocol == protocol
        assert metadata.direction == "outbound"
        assert metadata.endpoint_metadata.source_ip == "192.168.137.10"
        assert metadata.endpoint_metadata.destination_ip == "8.8.8.8"
