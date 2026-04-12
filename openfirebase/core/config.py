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

# Filtered Cloud Functions callable names — SDK internal method names
# and common false positives from the getHttpsCallable() bytecode walk.
FILTERED_CALLABLE_NAMES = [
    "getHttpsCallable",
    "getInstance",
    "functionName",
]

# All supported GCP regions for Firebase Cloud Functions enumeration.
# Ordered by likelihood: us-central1 (default) first, then remaining
# Tier 1, then Tier 2. Scanner should iterate in this order.
CLOUD_FUNCTIONS_REGIONS = [
    # Tier 1
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "europe-west1",
    "asia-east1",
    "asia-northeast1",
    "asia-northeast2",
    # Tier 1 (2nd gen only)
    "us-east5",
    "us-south1",
    "europe-north1",
    "europe-west4",
    "europe-west8",
    "europe-west9",
    "europe-southwest1",
    "me-west1",
    "africa-south1",
    # Tier 2
    "us-west2",
    "us-west3",
    "us-west4",
    "northamerica-northeast1",
    "northamerica-northeast2",
    "southamerica-east1",
    "southamerica-west1",
    "europe-west2",
    "europe-west3",
    "europe-west6",
    "europe-west10",
    "europe-west12",
    "europe-central2",
    "asia-east2",
    "asia-south1",
    "asia-south2",
    "asia-southeast1",
    "asia-southeast2",
    "asia-northeast3",
    "australia-southeast1",
    "australia-southeast2",
    "me-central1",
    "me-central2",
]

