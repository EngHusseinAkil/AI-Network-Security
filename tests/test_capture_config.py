import pytest
from network.capture_config import CaptureConfig


def test_disabled_default():
    assert CaptureConfig().enabled is False


@pytest.mark.parametrize("source", ["scapy", "fake"])
def test_allowed_sources(source):
    assert CaptureConfig(source=source, fake_source_permitted=source == "fake").source == source


def test_fake_requires_permission():
    with pytest.raises(ValueError):
        CaptureConfig(source="fake")


@pytest.mark.parametrize("value", [0, 10001, True, 1.5])
def test_queue_bounds(value):
    with pytest.raises(ValueError):
        CaptureConfig(queue_size=value)


@pytest.mark.parametrize("field", ["max_packets", "max_duration_seconds",
                                    "read_timeout_seconds", "stop_join_timeout_seconds"])
def test_numeric_booleans_rejected(field):
    with pytest.raises(ValueError):
        CaptureConfig(**{field: True})


@pytest.mark.parametrize("value", [" ", "\t"])
def test_empty_filter_becomes_none(value):
    assert CaptureConfig(capture_filter=value).capture_filter is None


@pytest.mark.parametrize("value", ["tcp\0", "udp\n", "x" * 257])
def test_filter_sanitization(value):
    with pytest.raises(ValueError):
        CaptureConfig(capture_filter=value)
