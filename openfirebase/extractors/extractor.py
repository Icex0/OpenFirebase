"""Firebase Extractor Module

This module contains :class:`FirebaseExtractor`, the orchestration
entry point for pulling Firebase items out of mobile app bundles.
Format-specific string extraction is delegated to stateless helpers:

* **Android APKs** — :mod:`.dex_extractor` produces a synthetic
  ``<resources>`` blob from the DEX string pool, bytecode-walked
  Firestore call sites, and ``assets/`` / ``res/raw/`` text resources.
  Apksigner integration for signing-cert extraction lives here.
* **iOS IPAs** — :mod:`.ipa_extractor` handles
  ``GoogleService-Info.plist``, bundled service-account JSONs, the
  Mach-O binary's printable strings, and hardcoded PEM private keys.

This module owns the cross-format pipeline: loading the regex
patterns, running them against the per-format blobs, filtering
(domains, collection names, known test keys), service-account JSON
parsing, deduplication, and thread-safe per-package result storage.
:meth:`process_apk` is the dispatch entry point that routes by file
extension.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tqdm import tqdm

from ..core.config import FILTERED_COLLECTION_VALUES, FILTERED_DOMAINS, FILTERED_PRIVATE_KEY_SUBSTRINGS, RED, RESET, YELLOW
from ..parsers.pattern_loader import get_firebase_patterns, get_pattern_metadata
from .dex_extractor import DexExtractor
from .ipa_extractor import IpaExtractor

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


# Per-path androguard APK object cache. Androguard parsing is
# expensive (manifest + resources.arsc + DEX index all get rebuilt on
# each ``APK(path)`` call) and non-deterministically flaky under memory
# pressure. ``process_apk`` would otherwise parse the same APK twice
# in one call — once for resources.arsc, once for signature / package
# name — so we memoize here and clear at the end of ``process_apk``.
# Keyed by ``str(path)`` so workers can ``clear`` without a Path dep.
_APK_CACHE: Dict[str, "APK"] = {}


def _get_cached_apk(apk_path: Path):
    """Return a memoized androguard APK object for ``apk_path``.

    Re-parsing the same APK multiple times in one worker doubles both
    the wall-clock time and the peak memory of extraction, and makes
    transient parse failures more likely under memory pressure. This
    cache guarantees a single parse per APK per ``process_apk`` call.
    """
    key = str(apk_path)
    cached = _APK_CACHE.get(key)
    if cached is not None:
        return cached
    apk = APK(apk_path)
    _APK_CACHE[key] = apk
    return apk


def _clear_cached_apk(apk_path: Path) -> None:
    """Drop the cached APK object for ``apk_path`` (call at end of scan)."""
    _APK_CACHE.pop(str(apk_path), None)


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

    @staticmethod
    def is_ipa(path: Path) -> bool:
        """Return True if ``path`` looks like an iOS .ipa bundle."""
        return IpaExtractor.is_ipa(path)

    def extract_strings_xml_content(self, apk_path: Path, on_dex=None) -> str:
        """Extract string resources from a mobile bundle.

        Dispatches on file extension. ``.ipa`` is delegated to
        :class:`IpaExtractor`. For ``.apk`` we combine three sources
        into one synthetic ``<resources>`` blob the regex pipeline can
        scan in a single pass:

        1. ``resources.arsc`` strings (the historical fast-path source).
        2. The DEX string pool from every ``classes*.dex`` — covers
           Java/Kotlin string literals (Firebase URLs, API keys,
           Firestore collection names, hardcoded PEM blocks).
        3. Text files bundled in ``assets/`` and ``res/raw/`` — covers
           Firebase config blobs that ship as JSON/XML rather than as
           Java literals.

        Together these match what the JADX deep-mode path catches for
        OpenFirebase's regex set, without spawning a JVM.
        """
        if IpaExtractor.is_ipa(apk_path):
            return IpaExtractor.extract_strings_xml_content(apk_path)
        try:
            # 1) strings.xml from resources.arsc (historical source).
            arsc_lines: List[str] = []
            try:
                apk = _get_cached_apk(apk_path)
                resources = apk.get_android_resources()
                if resources:
                    string_resources = resources.get_strings_resources()
                    if isinstance(string_resources, dict):
                        for string_id, string_value in string_resources.items():
                            if isinstance(string_value, str):
                                arsc_lines.append(
                                    f'<string name="{string_id}">{string_value}</string>',
                                )
                    elif isinstance(string_resources, bytes):
                        # Older androguard returns the raw XML bytes —
                        # decode and inline as one chunk so the regex
                        # loop still sees the values.
                        try:
                            arsc_lines.append(string_resources.decode("utf-8"))
                        except UnicodeDecodeError:
                            pass
                    else:
                        tqdm.write(
                            f"{YELLOW}[WARNING]{RESET} resources.arsc returned unexpected type "
                            f"({type(string_resources).__name__}) for {apk_path.name}"
                        )
                else:
                    tqdm.write(
                        f"{YELLOW}[WARNING]{RESET} resources.arsc returned None for {apk_path.name} "
                        f"— resource strings will be missing from results"
                    )
            except Exception as e:
                tqdm.write(
                    f"{RED}[X]{RESET} resources.arsc parse failed for {apk_path.name}: "
                    f"{type(e).__name__}: {e}"
                )

            # 2) DEX string pool + 3) assets/ and res/raw/ text files.
            dex_blob = DexExtractor.build_strings_blob(apk_path, on_dex=on_dex)

            if not arsc_lines and not dex_blob:
                return ""

            blob_parts: List[str] = ["<resources>"]
            blob_parts.extend(arsc_lines)
            if dex_blob:
                blob_parts.append(dex_blob)
            blob_parts.append("</resources>")
            return "\n".join(blob_parts)

        except Exception as e:
            tqdm.write(
                f"{RED}[X]{RESET} extract_strings_xml_content failed for {apk_path.name}: "
                f"{type(e).__name__}: {e}"
            )
            return ""

    def _extract_with_timeout(self, apk_path: Path, on_dex=None) -> List[Tuple[str, str]]:
        """Extract Firebase items with a 2-minute timeout."""
        firebase_items = []
        seen_links = set()  # Track seen links to avoid duplicates

        try:
            # Extracting strings.xml
            content = self.extract_strings_xml_content(apk_path, on_dex=on_dex)

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

                    # Filter out template fragments like "default-rtdb.firebaseio.com"
                    if link.lower().startswith("default-rtdb."):
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

        except Exception as e:
            tqdm.write(
                f"{RED}[X]{RESET} _extract_with_timeout failed for {apk_path.name}: "
                f"{type(e).__name__}: {e}"
            )

        return firebase_items

    def _extract_service_accounts_from_apk(self, apk_path: Path) -> List[Dict[str, str]]:
        """Extract service account credentials from APK assets/ and res/raw/ directories.

        Uses androguard to read files directly from the APK without decompilation.

        Returns:
            List of dicts with keys: client_email, private_key, project_id

        """
        service_accounts = []
        seen_emails = set()

        try:
            apk = APK(apk_path)

            # Check all files in the APK for service account JSON
            for filepath in apk.get_files():
                # Only check assets/ and res/raw/ directories, and .json files at root
                lower_path = filepath.lower()
                if not (
                    lower_path.startswith("assets/")
                    or lower_path.startswith("res/raw")
                    or (lower_path.endswith(".json") and "/" not in filepath)
                ):
                    continue

                if not lower_path.endswith(".json"):
                    continue

                try:
                    file_content = apk.get_file(filepath)
                    if not file_content:
                        continue
                    content = file_content.decode("utf-8", errors="ignore")
                    sa = self._parse_service_account_json(content)
                    if sa and sa["client_email"] not in seen_emails:
                        seen_emails.add(sa["client_email"])
                        service_accounts.append(sa)
                except Exception:
                    pass

        except Exception:
            pass

        return service_accounts

    @staticmethod
    def _parse_service_account_json(content: str) -> Optional[Dict[str, str]]:
        """Try to parse a service account JSON from file content."""
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return None

        if not isinstance(data, dict):
            return None

        if data.get("type") != "service_account":
            return None

        client_email = data.get("client_email", "")
        private_key = data.get("private_key", "")
        project_id = data.get("project_id", "")

        if client_email and private_key and "-----BEGIN" in private_key:
            return {
                "client_email": client_email,
                "private_key": private_key,
                "project_id": project_id,
            }
        return None

    def extract_from_apk(self, apk_path: Path, on_dex=None) -> List[Tuple[str, str]]:
        """Extract Firebase items from a single APK/IPA file."""
        return self._extract_with_timeout(apk_path, on_dex=on_dex)

    def get_apk_files(self) -> List[Path]:
        """Get all APK files from the input folder."""
        from ..utils import get_apk_files
        return get_apk_files(self.input_folder)

    @staticmethod
    def _is_known_test_key(pem: str) -> bool:
        """Return True if ``pem`` matches a known test/demo private key."""
        return any(sub in pem for sub in FILTERED_PRIVATE_KEY_SUBSTRINGS)

    def process_apk(self, apk_path: Path, on_dex=None, on_stage=None) -> List[Tuple[str, str]]:
        """Process a single mobile bundle (.apk or .ipa).

        The historical name is preserved for call-site compatibility,
        but the method now handles both Android APKs and iOS IPAs by
        dispatching on file extension.

        ``on_dex`` is invoked once per ``classes*.dex`` (Android only).
        ``on_stage`` is invoked once per logical IPA work stage with a
        short label string, so callers can drive a stage-based progress
        bar (the IPA path has no natural per-chunk milestone like DEX
        files).
        """
        firebase_items = self.extract_from_apk(apk_path, on_dex=on_dex)

        if IpaExtractor.is_ipa(apk_path):
            # iOS path: scan for bundled service account JSONs and pull
            # the CFBundleIdentifier as the result key. There is no
            # certificate-hash equivalent for Firebase API key
            # restrictions on iOS — only the bundle ID matters.
            if on_stage is not None:
                on_stage("Extracting service accounts")
            service_accounts = IpaExtractor.extract_service_accounts(
                apk_path, self._parse_service_account_json,
            )
            for sa in service_accounts:
                if self._is_known_test_key(sa["private_key"]):
                    continue
                firebase_items.append(("Service_Account_Email", sa["client_email"]))
                firebase_items.append(("Service_Account_Private_Key", sa["private_key"]))
                if sa["project_id"]:
                    firebase_items.append(("Service_Account_Project_ID", sa["project_id"]))

            # Surface PEM private-key blocks hardcoded directly in the
            # Mach-O binary as a standalone finding. These are not
            # tied to a discoverable client_email (the linker may dedup,
            # reorder, or LTO across translation units), so they don't
            # flow into the SA auth pipeline — they're for the operator
            # to investigate manually.
            if on_stage is not None:
                on_stage("Recovering hardcoded PEM keys")
            for pem in IpaExtractor.extract_hardcoded_pem_keys(apk_path):
                if not self._is_known_test_key(pem):
                    firebase_items.append(("Hardcoded_Private_Key", pem))

            if on_stage is not None:
                on_stage("Reading bundle identifier")
            bundle_id = IpaExtractor.extract_bundle_id(apk_path)
            package_name = bundle_id if bundle_id else apk_path.stem
            if bundle_id:
                firebase_items.append(("IPA_Bundle_ID", bundle_id))
        else:
            # Android path.
            service_accounts = self._extract_service_accounts_from_apk(apk_path)
            for sa in service_accounts:
                if self._is_known_test_key(sa["private_key"]):
                    continue
                firebase_items.append(("Service_Account_Email", sa["client_email"]))
                firebase_items.append(("Service_Account_Private_Key", sa["private_key"]))
                if sa["project_id"]:
                    firebase_items.append(("Service_Account_Project_ID", sa["project_id"]))

            # Recover PEM private-key blocks pasted directly into
            # Java/Kotlin source. Pair with a gserviceaccount.com email
            # only if both appear exactly once in the same DEX file —
            # otherwise emit standalone (mirrors the iOS approach,
            # since DEX-pool grouping is weaker than per-class).
            seen_sa_emails = {sa["client_email"] for sa in service_accounts}
            for pem, paired_email in DexExtractor.extract_hardcoded_pem_keys(apk_path):
                if self._is_known_test_key(pem):
                    continue
                if paired_email and paired_email not in seen_sa_emails:
                    firebase_items.append(("Service_Account_Email", paired_email))
                    firebase_items.append(("Service_Account_Private_Key", pem))
                    seen_sa_emails.add(paired_email)
                else:
                    firebase_items.append(("Hardcoded_Private_Key", pem))

            from .signature_extractor import SignatureExtractor
            # Reuse the androguard APK object that extract_strings_xml_content
            # already parsed (if any) to avoid a second full APK parse.
            cached_apk = _APK_CACHE.get(str(apk_path))
            cert_sha1_list, apk_package_name = SignatureExtractor.extract_apk_signature(
                apk_path, apk=cached_apk
            )

            package_name = apk_package_name if apk_package_name else apk_path.stem

            for cert_sha1 in cert_sha1_list:
                firebase_items.append(("APK_Certificate_SHA1", cert_sha1))
            if apk_package_name:
                firebase_items.append(("APK_Package_Name", apk_package_name))

        if firebase_items:
            self.results[package_name] = firebase_items

        # Drop cached DEX strings now that both consumers have run.
        if not IpaExtractor.is_ipa(apk_path):
            DexExtractor.clear_cache(apk_path)
            # Drop the cached androguard APK object too so the worker's
            # memory footprint doesn't grow unbounded across many APKs.
            _clear_cached_apk(apk_path)

        return firebase_items

    def get_results(self) -> Dict[str, List[Tuple[str, str]]]:
        """Get the current results."""
        return self.results.copy()
