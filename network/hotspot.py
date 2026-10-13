"""Safe, passive Windows hotspot discovery helpers.

The capture engine still owns one native Scapy interface.  This module only
resolves that interface from the configured local network and exposes current
OS neighbor information for the operator-facing device list.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .capture_exceptions import CaptureSourceUnavailableError


@dataclass(frozen=True, slots=True)
class ConnectedDevice:
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "seen"
    selected: bool = True


def _network(cidr: str):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except (TypeError, ValueError) as exc:
        raise CaptureSourceUnavailableError("Hotspot network CIDR is invalid") from exc


def gateway_for_network(cidr: str) -> str:
    network = _network(cidr)
    hosts = network.hosts()
    try:
        return str(next(hosts))
    except StopIteration as exc:
        raise CaptureSourceUnavailableError("Hotspot network has no host address") from exc


def resolve_hotspot_interface(cidr: str, interface_addresses: Iterable[tuple[str, str]]) -> tuple[str, str]:
    """Resolve exactly one Scapy interface whose IPv4 address is on *cidr*.

    A unique gateway address wins when several candidate interfaces exist; all
    other ambiguous or empty results fail closed.
    """
    network = _network(cidr)
    gateway = gateway_for_network(cidr)
    candidates = []
    for native, address in interface_addresses:
        try:
            parsed = ipaddress.ip_address(str(address))
        except ValueError:
            continue
        if parsed.version == 4 and parsed in network:
            candidates.append((str(native), str(address)))
    gateway_candidates = [item for item in candidates if item[1] == gateway]
    if len(gateway_candidates) == 1:
        return gateway_candidates[0]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise CaptureSourceUnavailableError("No hotspot capture interface matches the configured network")
    raise CaptureSourceUnavailableError("Hotspot capture interface detection is ambiguous")


def _clean_mac(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip().replace("-", ":").upper()
    parts = value.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return None
    try:
        int("".join(parts), 16)
    except ValueError:
        return None
    if value == "FF:FF:FF:FF:FF:FF":
        return None
    return value


def _safe_hostname(ip: str, resolver: Callable[[str], str] = socket.gethostbyaddr) -> Optional[str]:
    try:
        name = resolver(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None
    return name if isinstance(name, str) and name and name != ip else None


def discover_connected_devices(
    cidr: str,
    neighbor_rows: Optional[Iterable[dict]] = None,
    hostname_resolver: Callable[[str], str] = socket.gethostbyaddr,
) -> tuple[ConnectedDevice, ...]:
    """Return passive OS-neighbor entries on the hotspot subnet.

    ``neighbor_rows`` is injectable for tests and alternate OS providers.  No
    active scan is performed.  Gateway, broadcast, multicast, malformed, and
    incomplete entries are excluded.
    """
    network = _network(cidr)
    gateway = gateway_for_network(cidr)
    rows = read_windows_neighbors() if neighbor_rows is None else neighbor_rows
    devices = {}
    for row in rows:
        ip = str(row.get("ip_address") or row.get("IPAddress") or "").strip()
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if (address.version != 4 or address not in network
                or address in (network.network_address, network.broadcast_address)
                or ip == gateway
                or address.is_multicast or address.is_unspecified or address.is_reserved):
            continue
        mac = _clean_mac(row.get("mac_address") or row.get("LinkLayerAddress"))
        state = str(row.get("status") or row.get("State") or "seen").strip().lower()
        if state in {"unreachable", "invalid", "incomplete"}:
            continue
        devices[ip] = ConnectedDevice(
            ip_address=ip,
            mac_address=mac,
            hostname=(row.get("hostname") or row.get("Name") or _safe_hostname(ip, hostname_resolver)),
            status=state or "seen",
            selected=True,
        )
    return tuple(sorted(devices.values(), key=lambda item: ipaddress.ip_address(item.ip_address)))


def read_windows_neighbors() -> tuple[dict, ...]:
    """Read the Windows neighbor table without sending traffic."""
    command = (
        "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue "
        "| Select-Object IPAddress,LinkLayerAddress,State "
        "| ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=3, check=False,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return ()
        value = json.loads(completed.stdout)
        return tuple(value if isinstance(value, list) else [value]) if isinstance(value, (dict, list)) else ()
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return ()
