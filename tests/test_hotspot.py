import pytest

from network.capture_exceptions import CaptureSourceUnavailableError
from network.capture_models import CapturedPacketMetadata, FlowEndpointMetadata
from network.hotspot import discover_connected_devices, resolve_hotspot_interface
from network.hotspot import ConnectedDevice
from dashboard.capture_service import DashboardCaptureService
from network.flow_aggregation_service import FlowAggregationService
from network.flow_config import MetadataFlowConfig
from network.flow_models import FlowCompletionReason
from datetime import datetime, timezone


def test_hotspot_interface_prefers_unique_gateway_address():
    assert resolve_hotspot_interface("192.168.137.0/24", [
        ("wifi-client", "192.168.137.20"),
        ("hotspot", "192.168.137.1"),
    ]) == ("hotspot", "192.168.137.1")


def test_ambiguous_hotspot_interfaces_fail_closed():
    with pytest.raises(CaptureSourceUnavailableError, match="ambiguous"):
        resolve_hotspot_interface("192.168.137.0/24", [
            ("one", "192.168.137.2"), ("two", "192.168.137.3"),
        ])


def test_no_hotspot_interface_fails_closed():
    with pytest.raises(CaptureSourceUnavailableError, match="No hotspot"):
        resolve_hotspot_interface("192.168.137.0/24", [("ethernet", "10.0.0.2")])


def test_neighbor_discovery_excludes_gateway_invalid_and_stale_entries():
    devices = discover_connected_devices("192.168.137.0/24", [
        {"IPAddress": "192.168.137.1", "LinkLayerAddress": "AA-BB-CC-DD-EE-01", "State": "Reachable"},
        {"IPAddress": "192.168.137.16", "LinkLayerAddress": "BA-6B-00-00-00-16", "State": "Reachable"},
        {"IPAddress": "192.168.137.17", "LinkLayerAddress": "BA-6B-00-00-00-17", "State": "Stale", "Name": "phone-2"},
        {"IPAddress": "192.168.137.255", "LinkLayerAddress": "FF-FF-FF-FF-FF-FF", "State": "Reachable"},
        {"IPAddress": "192.168.137.18", "LinkLayerAddress": "00-00-00-00-00-00", "State": "Incomplete"},
    ], hostname_resolver=lambda ip: (_ for _ in ()).throw(OSError()))

    assert [item.ip_address for item in devices] == ["192.168.137.16", "192.168.137.17"]
    assert devices[0].selected is True
    assert devices[1].hostname == "phone-2"


class _Discovery:
    def __init__(self):
        self.options = []

    def refresh(self, provider):
        self.options = [type("Option", (), {"key": native, "display_label": label})()
                        for native, label in provider.discover_interfaces()]
        return tuple(self.options)

    def list_options(self):
        return tuple(self.options)


class _Capture:
    def __init__(self):
        self.calls = []

    def start_capture(self, key, selected):
        self.calls.append((key, selected))


def test_dashboard_devices_are_selected_by_default_and_one_source_is_used():
    discovery = _Discovery()
    capture = _Capture()
    rows = [[
        ConnectedDevice("192.168.137.16", "AA:00:00:00:00:16"),
        ConnectedDevice("192.168.137.17", "AA:00:00:00:00:17"),
    ]]
    provider = type("Provider", (), {"discover_interfaces": lambda self: (("native-hotspot", "Hotspot"),)})()
    service = DashboardCaptureService(
        capture, discovery, lambda: provider, "192.168.137.0/24",
        device_provider=lambda cidr: tuple(rows[-1]),
    )

    assert {item["ip_address"] for item in service.refresh_devices()
            if item["selected"]} == {"192.168.137.16", "192.168.137.17"}
    service.selected_device_ips(["192.168.137.17"])
    assert service.selected_device_ips([]) == frozenset()
    service.selected_device_ips(["192.168.137.17"])
    rows.append([*rows[-1], ConnectedDevice("192.168.137.18", "AA:00:00:00:00:18")])
    refreshed = service.refresh_devices()
    assert next(item for item in refreshed if item["ip_address"] == "192.168.137.18")["selected"] is True
    service.start_monitoring(["192.168.137.17"])

    assert len(capture.calls) == 1
    assert capture.calls[0][0] == "native-hotspot"
    assert capture.calls[0][1] == frozenset({"192.168.137.17"})


def test_three_selected_device_flows_remain_separate_and_explicitly_associated():
    aggregator = FlowAggregationService(MetadataFlowConfig())
    for ip in ("192.168.137.16", "192.168.137.129", "192.168.137.236"):
        metadata = CapturedPacketMetadata(
            datetime.now(timezone.utc), 100, "TCP", "hotspot", "outbound",
            FlowEndpointMetadata(ip, "8.8.8.8"),
        )
        aggregator.accept(metadata, source_mode="scapy", capture_session_id="session")

    completed = aggregator.flush(FlowCompletionReason.CAPTURE_SESSION_STOPPED, "session")
    assert {flow.monitored_device_ip for flow in completed} == {
        "192.168.137.16", "192.168.137.129", "192.168.137.236"
    }
    assert len(completed) == 3
