"""
AI Detection Engine.

This package provides the core machine learning and behavioral anomaly detection
capabilities for the network security platform. It relies strictly on the
runtime feature schema provided by the network engine.
"""

from ai.constants import (
    PACKET_SCHEMA_VERSION,
    FLOW_SCHEMA_VERSION,
    CANONICAL_LABELS
)

__all__ = [
    "PACKET_SCHEMA_VERSION",
    "FLOW_SCHEMA_VERSION",
    "CANONICAL_LABELS"
]
