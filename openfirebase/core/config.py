"""Configuration Module for OpenFirebase

Centralized configuration for all constants and settings.
"""

# Version information
VERSION = "1.2.0"

# ANSI color codes - Using 256-color mode for consistency across terminals
GREEN = "\033[38;5;46m"  # Bright green for success
RED = "\033[38;5;196m"   # Bright red for errors
ORANGE = "\033[38;5;208m" # Orange for warnings
BLUE = "\033[38;5;177m"   # Blue for information
YELLOW = "\033[38;5;226m" # Bright yellow for warnings
LIME = "\033[38;5;118m" # Bright lime
GREY = "\033[90m"  # Dark grey color for unknown status
GOLD = "\033[33m" # Gold for locked status
RESET = "\033[0m"

# Firebase Scanner Constants
RESPONSE_CONTENT_MAX_LENGTH = 200
DEFAULT_TIMEOUT = 10
DEFAULT_RATE_LIMIT = 1.0

# Status codes
STATUS_OK = "200"
STATUS_BAD_REQUEST = "400"
STATUS_UNAUTHORIZED = "401"
STATUS_FORBIDDEN = "403"
STATUS_NOT_FOUND = "404"
STATUS_PRECONDITION_FAILED = "412"
STATUS_LOCKED = "423"
STATUS_TOO_MANY_REQUESTS = "429"

# Android Build Tools Configuration
ANDROID_BUILD_TOOLS_URL = "https://dl.google.com/android/repository/build-tools_r33.0.2-windows.zip"
ANDROID_BUILD_TOOLS_FOLDER = "android-13"

# File Configuration
DEFAULT_CONFIG_PATH = "firebase_rules.json"
DEFAULT_OUTPUT_DIR = "results"

# Invalid Project IDs to filter out
INVALID_PROJECT_IDS = {
    "-default-rtdb",
    "chrome-devtools-frontend"
}

# Filtered domains/links to exclude from extraction
FILTERED_DOMAINS = [
    "admob-gmats.uc.r.appspot.com",
    "example.appspot.com",
    "myservice.appspot.com",
    "test.firebaseio.com",
    "demo.firebaseio.com",
    "chrome-devtools-frontend",
]

# Known test/demo private keys shipped inside third-party library jars.
# Matched by a unique substring of the base64 body so the check is
# version-stable (the actual key bytes never change for test fixtures).
#
# Sources:
#   - google-api-client-java TestCertificates.CA_KEY
#   - google-api-client-java TestCertificates.FOO_BAR_COM_KEY
#   - Netty BogusKeyManagerFactory PROBING_KEY (self-signed example.com test cert)
FILTERED_PRIVATE_KEY_SUBSTRINGS = [
    "QDN5Q1zhtJYeE5N",   # google-api-client TestCertificates.CA_KEY
    "QCzFVKJOkqTmyyj",   # google-api-client TestCertificates.FOO_BAR_COM_KEY
    "CCBtayYNDrM3NFnk",  # Netty BogusKeyManagerFactory PROBING_KEY
]

# Filtered collection values to exclude from extraction
FILTERED_COLLECTION_VALUES = [
    "service_disabled",
    "access_denied",
    "Signal collection failed:",
    "Received empty bid id",
]

