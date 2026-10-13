from network.live_direction import classify_live_direction


LIVE_CIDR = "192.168.137.0/24"


def test_phone_to_internet_is_outbound():
    assert classify_live_direction("192.168.137.16", "8.8.8.8", LIVE_CIDR) == "outbound"


def test_internet_to_phone_is_inbound():
    assert classify_live_direction("8.8.8.8", "192.168.137.16", LIVE_CIDR) == "inbound"


def test_two_hotspot_addresses_are_internal():
    assert classify_live_direction("192.168.137.16", "192.168.137.1", LIVE_CIDR) == "internal"


def test_absent_live_override_preserves_unknown_behavior():
    assert classify_live_direction("192.168.137.16", "8.8.8.8", None) == "unknown"
