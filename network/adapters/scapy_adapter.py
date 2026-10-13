"""
Scapy Adapter.

Converts live Scapy packet objects into safe, payload-free dictionaries 
that are compatible with `network/parser.py`.
"""

import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from network.interfaces import validate_interface_name
from network.constants import DEFAULT_MAX_PACKET_SAMPLE_COUNT, DEFAULT_MAX_CAPTURE_DURATION_SECONDS
from network.capture_exceptions import (
    CaptureMissingDependencyError, CapturePermissionError,
    CaptureSourceUnavailableError,
)
from network.capture_models import CapturedPacketMetadata, FlowEndpointMetadata
from network.live_direction import classify_live_direction
from network.hotspot import resolve_hotspot_interface

logger = logging.getLogger(__name__)


class ScapyInterfaceProvider:
    """Typed discovery provider. Calling it is the only discovery-time Scapy import."""

    def discover_interfaces(self):
        try:
            scapy = _get_scapy_lib()
            return tuple((name, name) for name in scapy.get_if_list())
        except ImportError as exc:
            raise CaptureMissingDependencyError("Scapy is unavailable") from exc
        except PermissionError as exc:
            raise CapturePermissionError("Interface discovery is not permitted") from exc
        except OSError as exc:
            raise CaptureSourceUnavailableError("Interface discovery is unavailable") from exc


class ScapyHotspotInterfaceProvider:
    """Resolve the one Scapy/Npcap adapter serving the configured hotspot."""

    def __init__(self, local_network_cidr):
        self._local_network_cidr = local_network_cidr

    def discover_interfaces(self):
        if not self._local_network_cidr:
            raise CaptureSourceUnavailableError(
                "LIVE_LOCAL_NETWORK_CIDR is required for hotspot monitoring"
            )
        try:
            scapy = _get_scapy_lib()
            pairs = []
            for native in scapy.get_if_list():
                try:
                    address = scapy.get_if_addr(native)
                except (AttributeError, OSError, ValueError):
                    continue
                pairs.append((native, address))
            selected, address = resolve_hotspot_interface(
                self._local_network_cidr, pairs
            )
            return ((selected, f"Hotspot adapter ({address})"),)
        except ImportError as exc:
            raise CaptureMissingDependencyError("Scapy is unavailable") from exc
        except PermissionError as exc:
            raise CapturePermissionError("Hotspot interface discovery is not permitted") from exc
        except OSError as exc:
            raise CaptureSourceUnavailableError("Hotspot interface discovery is unavailable") from exc


class ScapyPacketSource:
    """Bounded, thread-free Scapy source returning only safe metadata."""

    def __init__(self, interface_key, local_network_cidr=None):
        self._interface_key = interface_key
        self._local_network_cidr = local_network_cidr
        self._native_interface = self._config = None
        self._stopped = self._closed = False

    def list_interfaces(self):
        return [native for native, _ in ScapyInterfaceProvider().discover_interfaces()]

    def open(self, native_interface, config):
        try:
            _get_scapy_lib()
        except ImportError as exc:
            raise CaptureMissingDependencyError("Scapy is unavailable") from exc
        self._native_interface, self._config = native_interface, config

    def read_metadata(self, timeout):
        if self._stopped or self._closed:
            return None
        kwargs = {
            "iface": self._native_interface, "count": 1, "timeout": timeout,
            "store": True, "promisc": self._config.promiscuous,
        }
        if self._config.capture_filter:
            kwargs["filter"] = self._config.capture_filter
        try:
            packets = _get_scapy_lib().sniff(**kwargs)
        except ImportError as exc:
            raise CaptureMissingDependencyError("Scapy is unavailable") from exc
        except PermissionError as exc:
            raise CapturePermissionError("Capture permission denied") from exc
        except OSError as exc:
            raise CaptureSourceUnavailableError("Capture source unavailable") from exc
        if not packets:
            return None
        packet = packets[0]
        protocol = "OTHER"
        try:
            IP, TCP, UDP, ICMP = _get_scapy_layers()
            # Live capture sees ordinary layer-2 traffic as well as IPv4.
            # Only IPv4 packets have the endpoint contract used below;
            # unsupported frames, including IPv6, are intentionally ignored
            # at this boundary because IPv6 is not part of the live-flow
            # encoding contract.
            if not packet.haslayer(IP):
                return None
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
        except ImportError as exc:
            raise CaptureMissingDependencyError("Scapy layers are unavailable") from exc
        ip_layer = packet[IP]
        timestamp = datetime.fromtimestamp(float(getattr(packet, "time", time.time())), timezone.utc)
        direction = classify_live_direction(
            ip_layer.src,
            ip_layer.dst,
            self._local_network_cidr,
        )
        return CapturedPacketMetadata(
            timestamp, len(packet), protocol, self._interface_key, direction,
            FlowEndpointMetadata(
                ip_layer.src, ip_layer.dst,
                getattr(packet, "src", None), getattr(packet, "dst", None),
            ),
        )

    def request_stop(self):
        self._stopped = True

    def close(self):
        self._closed = True

    def get_status(self):
        return {"stopped": self._stopped, "closed": self._closed}

def _get_scapy_lib():
    import scapy.all as scapy_lib
    return scapy_lib

def _get_scapy_layers():
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    return IP, TCP, UDP, ICMP

def _check_scapy_installed() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("scapy") is not None
    except Exception:
        return False


def is_scapy_available() -> bool:
    """Returns True if the Scapy library is installed."""
    return _check_scapy_installed()


def extract_scapy_metadata(scapy_packet, interface_name: str = "unknown") -> Optional[Dict[str, Any]]:
    """
    Extracts metadata from a Scapy packet and returns a dictionary compatible 
    with `network/parser.py`.
    
    Strictly avoids extracting or returning payloads, raw bytes, or body content.
    Returns None if the packet lacks an IP layer.
    """
    if not _check_scapy_installed():
        raise ImportError("Scapy is not installed.")
        
    try:
        IP, TCP, UDP, ICMP = _get_scapy_layers()
    except ImportError:
        raise ImportError("Failed to import scapy layers.")

    if not scapy_packet.haslayer(IP):
        return None
        
    ip_layer = scapy_packet[IP]
    
    packet_dict = {
        "timestamp": float(scapy_packet.time) if hasattr(scapy_packet, "time") else time.time(),
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "packet_size": len(scapy_packet),
        "ttl": ip_layer.ttl,
        "interface_name": interface_name
    }
    
    if scapy_packet.haslayer(TCP):
        tcp_layer = scapy_packet[TCP]
        packet_dict["protocol"] = "TCP"
        packet_dict["source_port"] = tcp_layer.sport
        packet_dict["destination_port"] = tcp_layer.dport
        
        # Scapy TCP flags are often presented as an integer or string-like FlagValue
        flags = str(tcp_layer.flags)
        packet_dict["tcp_flags"] = ",".join(list(flags.upper()))
        
    elif scapy_packet.haslayer(UDP):
        udp_layer = scapy_packet[UDP]
        packet_dict["protocol"] = "UDP"
        packet_dict["source_port"] = udp_layer.sport
        packet_dict["destination_port"] = udp_layer.dport
        
    elif scapy_packet.haslayer(ICMP):
        packet_dict["protocol"] = "ICMP"
        
    else:
        packet_dict["protocol"] = "OTHER"
        
    # We purposefully do not include any payload field
    return packet_dict


def validate_bpf_filter(bpf_filter: str) -> bool:
    """
    Validates a BPF filter string to prevent injection of unexpected characters.
    BPF strings shouldn't contain shell-like execution characters.
    """
    if not bpf_filter:
        return True
    if not isinstance(bpf_filter, str):
        return False
        
    # Block shell characters just in case it's passed down unsafely by underlying libs
    invalid_chars = [";", "&", "|", "`", "$", "<", ">", "\\"]
    if any(char in bpf_filter for char in invalid_chars):
        return False
    return True


def capture_packets(
    interface_name: Optional[str] = None, 
    packet_count: int = 10, 
    timeout: int = 10, 
    packet_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Safely captures packets from an interface using Scapy.
    Converts captured packets directly into safe metadata dictionaries.
    Never returns raw Scapy packets or payloads.
    """
    if not _check_scapy_installed():
        logger.error("Scapy is not available. Cannot capture packets.")
        return []
        
    # Validate interface
    if interface_name is not None:
        if not validate_interface_name(interface_name):
            logger.error(f"Invalid interface name provided: {interface_name}")
            raise ValueError(f"Invalid interface name: {interface_name}")
            
    # Validate filter
    if packet_filter is not None:
        if not validate_bpf_filter(packet_filter):
            logger.error("Invalid characters in BPF filter.")
            raise ValueError("Invalid BPF filter.")
            
    # Enforce safe limits
    safe_count = min(max(1, int(packet_count)), DEFAULT_MAX_PACKET_SAMPLE_COUNT)
    safe_timeout = min(max(1, int(timeout)), DEFAULT_MAX_CAPTURE_DURATION_SECONDS)
    
    try:
        scapy_lib = _get_scapy_lib()
    except ImportError:
        logger.error("Failed to import scapy.all.")
        return []
        
    kwargs = {
        "count": safe_count,
        "timeout": safe_timeout,
        "store": True  # We need to process them, but we drop raw bytes immediately after
    }
    
    if interface_name:
        kwargs["iface"] = interface_name
    if packet_filter:
        kwargs["filter"] = packet_filter
        
    try:
        # Sniff packets
        raw_packets = scapy_lib.sniff(**kwargs)
        
        # Convert to safe dictionaries immediately
        safe_dicts = []
        for raw_pkt in raw_packets:
            meta_dict = extract_scapy_metadata(raw_pkt, interface_name or "unknown")
            if meta_dict is not None:
                safe_dicts.append(meta_dict)
                
        return safe_dicts
        
    except PermissionError as e:
        logger.error(f"Permission denied during capture: {e}")
        return []
    except OSError as e:
        logger.error(f"OS/Driver error during capture (missing Npcap?): {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error during capture: {e}")
        return []
