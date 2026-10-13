"""
Constants for the AI Detection Engine.

Defines schemas, models, and label foundations.
"""

# Feature Schema Versions
PACKET_SCHEMA_VERSION = "1.0.0"
FLOW_SCHEMA_VERSION = "1.0.0"

# Model Configuration
BASELINE_MODEL_NAME = "random_forest_baseline"
RANDOM_SEED = 42
DEFAULT_TEST_SPLIT_RATIO = 0.2

# Model Artifact Conventions
MODEL_ARTIFACT_EXTENSION = ".joblib"
MODEL_METADATA_FILENAME = "metadata.json"

# Canonical Label Foundation
LABEL_BENIGN = "benign"
LABEL_DDOS = "ddos"
LABEL_PORT_SCAN = "port_scan"
LABEL_BRUTE_FORCE = "brute_force"
LABEL_BOTNET = "botnet"
LABEL_MALWARE = "malware"
LABEL_UNKNOWN = "unknown"

CANONICAL_LABELS = [
    LABEL_BENIGN,
    LABEL_DDOS,
    LABEL_PORT_SCAN,
    LABEL_BRUTE_FORCE,
    LABEL_BOTNET,
    LABEL_MALWARE,
    LABEL_UNKNOWN
]
