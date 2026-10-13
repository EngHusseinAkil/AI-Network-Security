"""
Constants module containing generic, reusable project constants.
Does not contain application logic or secrets.
"""

# Default file encodings
DEFAULT_ENCODING = "utf-8"

# Date and time formats
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DATE_FORMAT = "%Y-%m-%d"
TIME_FORMAT = "%H:%M:%S"
LOG_SAFE_DATETIME_FORMAT = "%Y%m%d_%H%M%S"

# Common file extensions
EXT_JSON = ".json"
EXT_LOG = ".log"
EXT_CSV = ".csv"

# Allowed environments
ENV_DEVELOPMENT = "development"
ENV_TESTING = "testing"
ENV_PRODUCTION = "production"

# Common Status Strings
STATUS_SUCCESS = "success"
STATUS_ERROR = "error"
STATUS_PENDING = "pending"
