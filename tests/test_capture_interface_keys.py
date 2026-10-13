import pytest
from network.capture_exceptions import CaptureInvalidInterfaceError
from network.interfaces import InterfaceDiscoveryService


class Provider:
    def __init__(self, values=(("native0", "Ethernet"),)):
        self.values = values
    def discover_interfaces(self):
        return self.values


def test_default_ttl_valid_before_and_invalid_at_expiry():
    now = [0.0]
    service = InterfaceDiscoveryService(clock=lambda: now[0])
    key = service.refresh(Provider())[0].key
    now[0] = 299.999
    assert service.resolve(key) == "native0"
    now[0] = 300.0
    with pytest.raises(CaptureInvalidInterfaceError):
        service.resolve(key)


def test_reads_do_not_extend_ttl():
    now = [0.0]
    service = InterfaceDiscoveryService(clock=lambda: now[0])
    key = service.refresh(Provider())[0].key
    now[0] = 200
    service.list_options()
    now[0] = 300
    with pytest.raises(CaptureInvalidInterfaceError):
        service.resolve(key)


def test_cache_bounded_to_64():
    service = InterfaceDiscoveryService()
    assert len(service.refresh(Provider((str(i), str(i)) for i in range(100)))) == 64


def test_failed_refresh_preserves_cache():
    service = InterfaceDiscoveryService()
    key = service.refresh(Provider())[0].key
    class Broken:
        def discover_interfaces(self):
            raise RuntimeError
    with pytest.raises(RuntimeError):
        service.refresh(Broken())
    assert service.resolve(key) == "native0"


def test_successful_refresh_invalidates_old_key():
    service = InterfaceDiscoveryService()
    old = service.refresh(Provider())[0].key
    service.refresh(Provider((("native1", "Wi-Fi"),)))
    with pytest.raises(CaptureInvalidInterfaceError):
        service.resolve(old)


def test_keys_are_opaque_and_random():
    service = InterfaceDiscoveryService()
    first = service.refresh(Provider())[0].key
    second = service.refresh(Provider())[0].key
    assert first != second and "native" not in first


def test_labels_sanitized_and_bounded():
    option = InterfaceDiscoveryService().refresh(Provider((("secret", "x\n" * 100),)))[0]
    assert "\n" not in option.display_label and len(option.display_label) <= 80


def test_duplicate_labels_resolve_independently():
    service = InterfaceDiscoveryService()
    options = service.refresh(Provider((("a", "Same"), ("b", "Same"))))
    assert {service.resolve(x.key) for x in options} == {"a", "b"}


def test_returned_collection_cannot_mutate_cache():
    service = InterfaceDiscoveryService()
    options = service.refresh(Provider())
    assert isinstance(options, tuple)
