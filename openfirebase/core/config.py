"""Configuration Module for OpenFirebase

Centralized configuration for all constants and settings.
"""

# Version information
VERSION = "1.0.0"

# ANSI color codes - Using 256-color mode for consistency across terminals
GREEN = "\033[38;5;46m"  # Bright green
RED = "\033[38;5;196m"   # Bright red
ORANGE = "\033[38;5;208m" # Orange (unchanged)
BLUE = "\033[38;5;177m"   # Blue (unchanged) 
YELLOW = "\033[38;5;226m" # Bright yellow
LIME = "\033[38;5;118m"  # Bright lime color
GREY = "\033[90m"  # Dark grey color for unknown status
GOLD = "\033[33m"  # Gold color for locked status
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

# JADX Configuration
JADX_VERSION = "1.5.2"
JADX_DOWNLOAD_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"

# Android Build Tools Configuration
ANDROID_BUILD_TOOLS_URL = "https://dl.google.com/android/repository/build-tools_r33.0.2-windows.zip"
ANDROID_BUILD_TOOLS_FOLDER = "android-13"

# JADX Processing Configuration
DEFAULT_TIMEOUT_SECONDS = 1800 # Wait 30 minutes for JADX before skipping

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
    "-default-rtdb.firebaseio.com", # If defined as getProjectId() + "-default-rtdb.firebaseio.com";
]

# Filtered collection values to exclude from extraction
FILTERED_COLLECTION_VALUES = [
    "service_disabled",
    "access_denied",
    "Signal collection failed:",
    "Received empty bid id",
]

