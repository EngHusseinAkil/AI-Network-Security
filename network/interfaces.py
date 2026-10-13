"""
Interface Discovery Abstraction.

Provides safe, OS-agnostic network interface discovery.
Supports synthetic injection for safe testing without admin privileges or live capture dependencies.
"""
import socket
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Protocol

from network.metadata import InterfaceMetadata
from network.capture_exceptions import CaptureInvalidInterfaceError


class InterfaceDiscoveryProvider(Protocol):
    def discover_interfaces(self) -> Iterable[tuple[str, str]]: ...


@dataclass(frozen=True, slots=True)
class SafeInterfaceOption:
    key: str
    display_label: str
    expires_at: float


class InterfaceDiscoveryService:
    """Injected process-local cache mapping random public keys to native IDs."""

    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 ttl: float = 300, max_entries: int = 64, logger=None):
        if not isinstance(ttl, (int, float)) or ttl <= 0:
            raise ValueError("ttl must be positive")
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or not 1 <= max_entries <= 64:
            raise ValueError("max_entries must be between 1 and 64")
        self._clock, self._ttl = clock, float(ttl)
        self._max_entries, self._logger = max_entries, logger
        self._entries = {}

    @staticmethod
    def _safe_label(value):
        label = "".join(ch if ch.isprintable() and ch not in "\r\n\t" else " " for ch in str(value))
        return " ".join(label.split())[:80] or "Network interface"

    def refresh(self, provider: InterfaceDiscoveryProvider):
        now, temporary = self._clock(), {}
        try:
            for native, label in provider.discover_interfaces():
                if len(temporary) >= self._max_entries:
                    break
                key = secrets.token_urlsafe(24)
                option = SafeInterfaceOption(key, self._safe_label(label), now + self._ttl)
                temporary[key] = (option, str(native))
        except Exception:
            if self._logger:
                self._logger.warning("Interface discovery failed", exc_info=True)
            raise
        self._entries = temporary
        return self.list_options()

    def clear_expired(self):
        now = self._clock()
        self._entries = {key: value for key, value in self._entries.items()
                         if value[0].expires_at > now}

    def list_options(self):
        self.clear_expired()
        return tuple(value[0] for value in self._entries.values())

    def resolve(self, key):
        self.clear_expired()
        try:
            return self._entries[key][1]
        except (KeyError, TypeError):
            raise CaptureInvalidInterfaceError("Unknown or expired interface key") from None

# A global registry for synthetic interfaces, used primarily for testing.
_synthetic_interfaces: List[InterfaceMetadata] = []
_use_synthetic: bool = False


def enable_synthetic_mode(interfaces: List[InterfaceMetadata]) -> None:
    """
    Enables synthetic mode and injects mock interfaces for testing.
    This bypasses any real OS network checks.
    """
    global _synthetic_interfaces, _use_synthetic
    _synthetic_interfaces = interfaces
    _use_synthetic = True


def disable_synthetic_mode() -> None:
    """Disables synthetic mode, returning the engine to real OS discovery."""
    global _synthetic_interfaces, _use_synthetic
    _synthetic_interfaces = []
    _use_synthetic = False


def mask_mac_address(mac: str) -> str:
    """
    Masks a MAC address for privacy.
    Example: '00:1A:2B:3C:4D:5E' becomes '00:1A:2B:**:**:**'.
    """
    if not mac or not isinstance(mac, str):
        return mac
    
    parts = mac.split(":")
    if len(parts) == 6:
        return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:**"
    
    parts_dash = mac.split("-")
    if len(parts_dash) == 6:
         return f"{parts_dash[0]}-{parts_dash[1]}-{parts_dash[2]}-**-**-**"
         
    return mac


def _get_real_interfaces() -> List[InterfaceMetadata]:
    """
    Retrieves real OS interfaces using lightweight standard library tools.
    Since we cannot depend on Scapy, Npcap, or psutil for this milestone,
    we provide a highly safe rudimentary implementation utilizing socket data.
    """
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except socket.error:
        ip = "127.0.0.1"
        
    name = "lo0" if ip == "127.0.0.1" else "eth0"
    ips = ["127.0.0.1", ip] if ip != "127.0.0.1" else ["127.0.0.1"]
    
    return [
        InterfaceMetadata(
            name=name,
            description="OS Default Interface (Standard Lib Fallback)",
            is_up=True,
            mac_address=mask_mac_address("00:00:00:00:00:00"),
            ip_addresses=ips
        )
    ]


def list_interfaces() -> List[InterfaceMetadata]:
    """
    Lists all available network interfaces.
    If synthetic mode is active, it returns the injected interfaces
    with MAC addresses dynamically masked for privacy.
    """
    if _use_synthetic:
        return [
            InterfaceMetadata(
                name=iface.name,
                description=iface.description,
                is_up=iface.is_up,
                mac_address=mask_mac_address(iface.mac_address),
                ip_addresses=iface.ip_addresses
            ) for iface in _synthetic_interfaces
        ]
    return _get_real_interfaces()


def get_active_interfaces() -> List[InterfaceMetadata]:
    """Returns only the network interfaces that are currently UP."""
    return [iface for iface in list_interfaces() if iface.is_up]


def validate_interface_name(name: str) -> bool:
    """
    Validates if an interface name is properly formatted and safe.
    Prevents command injection or path traversal strings.
    """
    if not isinstance(name, str) or not name.strip():
        return False
    
    invalid_chars = ["/", "\\", ";", "&", "|", "`", "$", "(", ")", "<", ">"]
    if any(char in name for char in invalid_chars):
        return False
        
    return True


def get_interface_by_name(name: str) -> Optional[InterfaceMetadata]:
    """
    Finds a specific network interface by its name.
    Raises ValueError if the name is unsafe.
    """
    if not validate_interface_name(name):
        raise ValueError(f"Invalid interface name: {name}")
    
    for iface in list_interfaces():
        if iface.name == name:
            return iface
    return None
