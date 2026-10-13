"""Dashboard-facing adapter over framework-neutral capture services."""
from datetime import datetime

from network.hotspot import discover_connected_devices


def serialize_capture_status(snapshot):
    return {
        "enabled": snapshot.enabled,
        "source": snapshot.source,
        "state": snapshot.state.name.lower(),
        "session_id": snapshot.session_id,
        "interface_key": snapshot.interface_key,
        "packet_count": snapshot.packet_count,
        "dropped_metadata_count": snapshot.dropped_metadata_count,
        "start_timestamp": _iso(snapshot.start_timestamp),
        "elapsed_duration": snapshot.elapsed_duration,
        "stop_reason": snapshot.stop_reason,
        "error_category": snapshot.error_category,
    }


def _iso(value: datetime | None):
    return value.isoformat().replace("+00:00", "Z") if value else None


class DashboardCaptureService:
    def __init__(self, capture_service, discovery_service, provider_factory,
                 local_network_cidr=None, device_provider=discover_connected_devices):
        self._capture = capture_service
        self._discovery = discovery_service
        self._provider_factory = provider_factory
        self._local_network_cidr = local_network_cidr
        self._device_provider = device_provider
        self._devices = ()
        self._explicit_selection = None

    def status(self):
        status = serialize_capture_status(self._capture.status_snapshot())
        status["devices"] = self.devices()
        status["hotspot_interface_detected"] = len(self._discovery.list_options()) == 1
        return status

    def interfaces(self):
        return self._discovery.list_options()

    @staticmethod
    def _serialize_device(device, selected_ips):
        return {
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "hostname": device.hostname,
            "status": device.status,
            "selected": device.ip_address in selected_ips,
        }

    def devices(self):
        selected = ({item.ip_address for item in self._devices}
                    if self._explicit_selection is None else self._explicit_selection)
        return tuple(self._serialize_device(item, selected) for item in self._devices)

    def refresh_interfaces(self):
        return self._discovery.refresh(self._provider_factory())

    def refresh_devices(self):
        discovered = tuple(self._device_provider(self._local_network_cidr)) if self._local_network_cidr else ()
        known = {item.ip_address for item in discovered}
        if self._explicit_selection is None:
            selected = known
        else:
            selected = (self._explicit_selection & known) | (known - {
                item.ip_address for item in self._devices
            })
        self._devices = discovered
        self._explicit_selection = selected
        return self.devices()

    def refresh_hotspot(self):
        interfaces = self.refresh_interfaces()
        return {"interfaces": interfaces, "devices": self.refresh_devices()}

    def selected_device_ips(self, values=None):
        known = {item.ip_address for item in self._devices}
        if values is None:
            return frozenset(known if self._explicit_selection is None else self._explicit_selection)
        selected = frozenset(str(value).strip() for value in values if str(value).strip()) & known
        self._explicit_selection = selected
        return selected

    def start(self, key):
        self._capture.start_capture(key)

    def start_monitoring(self, selected_ips=None):
        # Re-resolve at start time so a stale cached adapter can never become
        # an arbitrary capture target after hotspot topology changes.
        self.refresh_interfaces()
        options = self._discovery.list_options()
        if len(options) != 1:
            raise RuntimeError("Hotspot capture interface is unavailable or ambiguous")
        selected = self.selected_device_ips(selected_ips)
        self._capture.start_capture(options[0].key, selected)

    def stop(self):
        self._capture.stop_capture()
