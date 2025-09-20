"""Firebase Extractor Module

This module contains the FirebaseExtractor class that handles
extracting Firebase items from APK files by parsing strings.xml.
"""

import re
import threading
from pathlib import Path
from typing import Dict, List, Tuple

from ..core.config import FILTERED_COLLECTION_VALUES, FILTERED_DOMAINS
from ..parsers.pattern_loader import get_firebase_patterns, get_pattern_metadata

# Configure logging to suppress androguard debug messages
try:
    from loguru import logger

    # Remove all existing handlers and set level to WARNING to suppress DEBUG messages
    logger.remove()
    logger.add(lambda _: None, level="WARNING")
except ImportError:
    pass

# Import androguard modules
try:
    from androguard.core.apk import APK

    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


class FirebaseExtractor:
    """Extracts Firebase items from APK files by parsing strings.xml."""

    @property
    def FIREBASE_PATTERNS(self) -> Dict[str, str]:
        """Get Firebase patterns from centralized configuration."""
        return get_firebase_patterns()

    def __init__(self, input_folder: str):
        """Initialize the extractor with the input folder path."""
        self.input_folder = Path(input_folder)
        self.results: Dict[str, List[Tuple[str, str]]] = {}
        self.results_lock = threading.Lock()  # Thread-safe access to results

    def extract_strings_xml_content(self, apk_path: Path) -> str:
        """Extract string resources from APK using Android resource system, including all locale directories."""
        try:
            # Load the APK
            apk = APK(apk_path)

            # Get the APK's resources
            resources = apk.get_android_resources()
            if resources:
                # Get all string resources from ALL locales (no package name needed)
                package_name = apk.get_package()
                string_resources = resources.get_strings_resources()
                if string_resources:
                    # Found string resources
                    # Handle different return types from get_strings_resources
                    if isinstance(string_resources, dict):
                        # Convert to XML-like format for pattern matching
                        strings_xml_content = "<resources>\n"
                        for string_id, string_value in string_resources.items():
                            if isinstance(string_value, str):
                                strings_xml_content += f'<string name="{string_id}">{string_value}</string>\n'
                        strings_xml_content += "</resources>"
                        # Successfully extracted string resources
                        return strings_xml_content
                    if isinstance(string_resources, bytes):
                        # If it returns bytes, try to decode as XML
                        try:
                            strings_xml_content = string_resources.decode("utf-8")
                            # Successfully extracted string resources
                            return strings_xml_content
                        except UnicodeDecodeError:
                            # Could not decode string resources bytes as UTF-8
                            pass
                    else:
                        # Unexpected string_resources type
                        pass

            # No string resources found
            return ""

        except Exception:
            # Error loading APK
            return ""

    def _extract_with_timeout(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Extract Firebase items with a 2-minute timeout."""
        firebase_items = []
        seen_links = set()  # Track seen links to avoid duplicates

        try:
            # Extracting strings.xml
            content = self.extract_strings_xml_content(apk_path)

            if not content:
                return firebase_items

            # Get pattern metadata for capture group information
            pattern_metadata = get_pattern_metadata()

            # Search for Firebase patterns in the strings.xml content
            for header, pattern in self.FIREBASE_PATTERNS.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Use capture group information from configuration
                    pattern_info = pattern_metadata.get(header, {})
                    capture_group = pattern_info.get("capture_group", 0)

                    if (
                        capture_group == 1
                        and match.groups()
                        and len(match.groups()) > 0
                    ):
                        link = match.group(1)  # Get the captured value from group 1
                    else:
                        link = match.group(0)  # Get the full match

                    # Filter out common example/test domains
                    if any(
                        domain in link.lower()
                        for domain in FILTERED_DOMAINS
                    ):
                        continue

                    # Filter out collection values that are in the filtered list
                    if "Collection" in header:
                        if link.lower() in [value.lower() for value in FILTERED_COLLECTION_VALUES]:
                            continue

                    # Clean up the link (remove trailing slashes, etc.) - only for URL patterns
                    if header != "Firebase_Project_ID":
                        link = link.rstrip("/")

                    # Only add if we haven't seen this exact link before
                    if link not in seen_links:
                        firebase_items.append((header, link))
                        seen_links.add(link)

        except Exception:
            # Error processing APK
            pass

        return firebase_items

    def extract_from_apk(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Extract Firebase items from strings.xml in a single APK file with 2-minute timeout."""
        result = []
        exception = None

        def target():
            nonlocal result, exception
            try:
                result = self._extract_with_timeout(apk_path)
            except Exception as e:
                exception = e

        # Create thread for extraction
        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()

        # Wait for 2 minutes (120 seconds)
        thread.join(timeout=120)

        if thread.is_alive():
            # Extraction timeout (2 minutes) - skipping
            return []

        if exception:
            # Error processing APK
            return []

        return result

    def get_apk_files(self) -> List[Path]:
        """Get all APK files from the input folder."""
        from ..utils import get_apk_files
        return get_apk_files(self.input_folder)

    def process_apk(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Process a single APK file and return Firebase items."""
        firebase_items = self.extract_from_apk(apk_path)

        # Extract APK signature and package name for Remote Config
        from .signature_extractor import SignatureExtractor
        cert_sha1_list, apk_package_name = SignatureExtractor.extract_apk_signature(apk_path)

        # Use real package name if available, otherwise fall back to APK filename
        package_name = apk_package_name if apk_package_name else apk_path.stem

        # Add all SHA-1 certificate information to Firebase items
        for cert_sha1 in cert_sha1_list:
            firebase_items.append(("APK_Certificate_SHA1", cert_sha1))
        if apk_package_name:
            firebase_items.append(("APK_Package_Name", apk_package_name))

        if firebase_items:
            with self.results_lock:
                self.results[package_name] = firebase_items
        # Remove print statements - will be handled by main progress bar

        return firebase_items

    def get_results(self) -> Dict[str, List[Tuple[str, str]]]:
        """Get the current results."""
        return self.results.copy()
