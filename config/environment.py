from enum import Enum

class Environment(Enum):
    """Enumeration of supported application environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"
