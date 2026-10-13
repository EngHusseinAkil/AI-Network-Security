"""Runtime direction classification for live capture traffic."""

import ipaddress


def classify_live_direction(source_ip: str, destination_ip: str,
                            local_network_cidr: str | None) -> str:
    """Classify traffic relative to an optional live local network.

    An absent or invalid runtime override intentionally preserves the existing
    live-capture behavior: direction is unknown rather than inferred.
    """
    if not source_ip or not destination_ip or not local_network_cidr:
        return "unknown"
    try:
        network = ipaddress.ip_network(local_network_cidr, strict=False)
        source = ipaddress.ip_address(source_ip)
        destination = ipaddress.ip_address(destination_ip)
    except ValueError:
        return "unknown"

    source_local = source in network
    destination_local = destination in network
    if source_local and destination_local:
        return "internal"
    if source_local:
        return "outbound"
    if destination_local:
        return "inbound"
    return "unknown"
