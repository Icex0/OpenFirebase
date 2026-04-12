"""iOS IPA Extractor Module

Stateless helpers for pulling Firebase items out of an iOS ``.ipa``
bundle. Split out of ``extractor.py`` so the Android (APK) and iOS
extraction code don't compete for space in the same file.

What this module does NOT do:

* Parse Mach-O load commands or Obj-C metadata. The binary string
  scanner is a plain ``strings(1)``-equivalent printable-byte walker.
* Decrypt FairPlay-encrypted App Store binaries. Resources inside an
  ``.ipa`` are not encrypted; only the Mach-O ``__TEXT`` segment of a
  store-downloaded build is. Pull a decrypted copy off a jailbroken
  device (e.g. ``bagbak``) before scanning if you need binary strings.

Both ``GoogleService-Info.plist`` extraction and the binary string
scanner produce a synthetic ``<resources>...</resources>`` blob so the
existing ``firebase_rules.json`` regex patterns (used by the APK path)
match unchanged. iOS-only items that bypass the regex pipeline:

* ``IPA_Bundle_ID`` — pulled directly from ``Info.plist``.
* ``Hardcoded_Private_Key`` — emitted directly from a PEM regex against
  the binary.
"""

from __future__ import annotations

import plistlib
import re
import zipfile
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from ._patterns import PEM_PRIVATE_KEY_RE as _PEM_PRIVATE_KEY_RE


# Map iOS GoogleService-Info.plist keys to the canonical Android-style
# string-resource names that the existing Firebase regex patterns
# already match against. This lets the same pattern loop the APK path
# uses work unchanged for iOS.
IOS_PLIST_KEY_MAP: Dict[str, str] = {
    "API_KEY": "google_api_key",
    "GOOGLE_APP_ID": "google_app_id",
    "GCM_SENDER_ID": "gcm_defaultSenderId",
    "PROJECT_ID": "project_id",
    "STORAGE_BUCKET": "google_storage_bucket",
    "DATABASE_URL": "firebase_database_url",
    "BUNDLE_ID": "ios_bundle_id",
    "CLIENT_ID": "default_web_client_id",
    "REVERSED_CLIENT_ID": "ios_reversed_client_id",
}

# Filename patterns to match within an .ipa for the Firebase plist.
# Apps with multiple environments commonly ship variants like
# ``GoogleService-Info-Dev.plist`` / ``GoogleService-Info-Prod.plist``
# and select one at runtime via ``FirebaseOptions(contentsOfFile:)``,
# so we match any file whose basename starts with ``GoogleService-Info``
# and ends with ``.plist``.
_IOS_PLIST_PREFIX = "GoogleService-Info"
_IOS_PLIST_SUFFIX = ".plist"
_IOS_INFO_PLIST_NAME = "Info.plist"

# Minimum run length for a printable-ASCII sequence pulled out of the
# Mach-O binary. 6 mirrors GNU ``strings(1)`` and is long enough to
# skip random byte garbage while still catching short Firebase
# identifiers like project IDs.
_IOS_BINARY_MIN_STRING_LEN = 6
# Cap how much of a binary we read in one go. Real iOS app binaries
# rarely exceed ~150 MB even for large apps; the cap is here only as
# a safety net against pathological inputs.
_IOS_BINARY_MAX_BYTES = 256 * 1024 * 1024
# Pre-compiled byte regex matching runs of printable ASCII (0x20–0x7e),
# exactly what GNU ``strings(1)`` extracts by default.
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _IOS_BINARY_MIN_STRING_LEN)

# Resource file scanning — mirrors the APK path's ``_extract_resource_files``
# so Cordova/Ionic/React Native iOS apps have their JS/HTML scanned for
# Firebase URLs, callable function names, etc.
_RESOURCE_TEXT_EXTS = (".json", ".xml", ".txt", ".properties", ".cfg", ".conf", ".js", ".html")
_JS_RESOURCE_EXTS = (".js", ".html")
_JS_TEMPLATE_INTERPOLATION_RE = re.compile(r"\$\{.*?\}", re.DOTALL)
_MAX_RESOURCE_FILE_BYTES = 5 * 1024 * 1024
_MAX_TOTAL_RESOURCE_BYTES = 50 * 1024 * 1024


class IpaExtractor:
    """Stateless container of iOS .ipa parsing helpers.

    Methods are organized to mirror what the APK path produces — a
    synthetic strings.xml blob, a list of service-account dicts, and a
    package/bundle identifier — so :class:`FirebaseExtractor` can call
    them as drop-in replacements on the iOS branch.
    """

    @staticmethod
    def is_ipa(path: Path) -> bool:
        """Return True if ``path`` looks like an iOS .ipa bundle."""
        return path.suffix.lower() == ".ipa"

    # ------------------------------------------------------------------
    # Zip iteration
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_app_files(zf: zipfile.ZipFile) -> Iterator[zipfile.ZipInfo]:
        """Yield ZipInfo entries that live inside ``Payload/<App>.app/``.

        An .ipa is a zip with a single top-level ``Payload/`` directory
        containing one ``.app`` bundle. Restricting iteration to that
        bundle skips stray archive metadata.
        """
        for info in zf.infolist():
            name = info.filename
            if name.startswith("Payload/") and ".app/" in name and not info.is_dir():
                yield info

    @staticmethod
    def _is_firebase_plist(filename: str) -> bool:
        """Return True if ``filename`` is a Firebase config plist.

        Matches any basename starting with ``GoogleService-Info`` and
        ending in ``.plist`` to handle multi-environment builds that
        ship variants like ``GoogleService-Info-Prod.plist``.
        """
        basename = filename.rsplit("/", 1)[-1]
        return (
            basename.startswith(_IOS_PLIST_PREFIX)
            and basename.endswith(_IOS_PLIST_SUFFIX)
        )

    # ------------------------------------------------------------------
    # Plist + binary string extraction
    # ------------------------------------------------------------------

    @classmethod
    def extract_strings_xml_content(cls, ipa_path: Path) -> str:
        """Read every GoogleService-Info*.plist plus the Mach-O binary
        and return a single synthetic strings.xml blob the APK pattern
        loop can match.

        Multi-environment apps may ship one plist per environment; we
        concatenate all of them so downstream extraction picks up every
        project ID, API key, and bucket. The Mach-O is also walked for
        printable string runs and appended, so hardcoded API keys / RTDB
        URLs / storage buckets in compiled Swift/Obj-C source are
        caught by the same regex pipeline.

        Returns an empty string when no Firebase plist *and* no binary
        strings are found.
        """
        lines: List[str] = ["<resources>"]
        found_any = False

        try:
            with zipfile.ZipFile(ipa_path) as zf:
                for info in cls._iter_app_files(zf):
                    if not cls._is_firebase_plist(info.filename):
                        continue
                    try:
                        with zf.open(info) as fp:
                            plist = plistlib.load(fp)
                    except (plistlib.InvalidFileException, OSError, ValueError):
                        continue
                    if not isinstance(plist, dict):
                        continue

                    found_any = True
                    for plist_key, value in plist.items():
                        if value is None:
                            continue
                        # Map iOS keys to canonical Android-style names
                        # so the existing Firebase regex patterns match
                        # without modification.
                        canonical = IOS_PLIST_KEY_MAP.get(plist_key, plist_key)
                        lines.append(
                            f'<string name="{canonical}">{value}</string>'
                        )
        except (zipfile.BadZipFile, OSError):
            return ""
        except Exception:
            return ""

        # Append the binary string scan so the same Firebase patterns
        # catch hardcoded API keys / URLs in the Mach-O.
        binary_fragment = cls._extract_binary_strings_content(ipa_path)
        if binary_fragment:
            found_any = True
            lines.append(binary_fragment)

        # Append resource file scan (JS/HTML/JSON inside the app bundle)
        # so Cordova/Ionic/React Native apps have their Firebase URLs,
        # callable names, and Cloud Functions patterns caught.
        resource_fragment = cls._extract_resource_files(ipa_path)
        if resource_fragment:
            found_any = True
            lines.append(resource_fragment)

        if not found_any:
            return ""
        lines.append("</resources>")
        return "\n".join(lines)

    @classmethod
    def _extract_binary_strings_content(cls, ipa_path: Path) -> str:
        """Walk the iOS app binary for printable string runs and emit a
        synthetic strings.xml fragment.

        This is the iOS analogue of JADX source-level scanning on
        Android. Implementation mirrors GNU ``strings(1)``: extract
        every run of ``_IOS_BINARY_MIN_STRING_LEN`` or more
        printable-ASCII bytes. Pure stdlib — no ``lief``, no
        ``otool``, no shell-out.
        """
        binary = cls._read_executable(ipa_path)
        if not binary:
            return ""

        seen: set = set()
        lines: List[str] = []
        for match in _PRINTABLE_RUN_RE.finditer(binary):
            try:
                value = match.group(0).decode("ascii")
            except UnicodeDecodeError:
                continue
            if value in seen:
                continue
            seen.add(value)
            # Wrap each candidate string in a synthetic <string> element
            # with an "ios_binary" name so the existing pattern loop
            # treats it the same as an Android string resource. The
            # generic name lets the unanchored Firebase URL / API key /
            # storage-bucket regexes match anywhere in the value.
            lines.append(f'<string name="ios_binary">{value}</string>')

        if not lines:
            return ""
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Resource file scanning (JS/HTML/JSON inside the app bundle)
    # ------------------------------------------------------------------

    @classmethod
    def _extract_resource_files(cls, ipa_path: Path) -> str:
        """Walk text resources inside the .app bundle and emit a synthetic
        strings.xml fragment.

        iOS Cordova/Ionic apps bundle JS/HTML under the ``.app`` directory
        (analogous to ``assets/www/`` in APKs). React Native apps bundle
        ``main.jsbundle``. This method scans all text resource files so
        the Firebase regex pipeline catches Cloud Functions URLs, callable
        names (``httpsCallable``), and other patterns in JS source.
        """
        lines: List[str] = []
        total_bytes = 0
        try:
            with zipfile.ZipFile(ipa_path) as zf:
                for info in cls._iter_app_files(zf):
                    if info.is_dir():
                        continue
                    lower = info.filename.lower()
                    # Also match .jsbundle (React Native)
                    if not (lower.endswith(_RESOURCE_TEXT_EXTS) or lower.endswith(".jsbundle")):
                        continue
                    if info.file_size > _MAX_RESOURCE_FILE_BYTES:
                        continue
                    if total_bytes + info.file_size > _MAX_TOTAL_RESOURCE_BYTES:
                        break
                    try:
                        with zf.open(info) as fp:
                            raw = fp.read()
                    except Exception:
                        continue
                    total_bytes += len(raw)
                    try:
                        text = raw.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    # Strip JS template literal interpolations
                    if lower.endswith(_JS_RESOURCE_EXTS) or lower.endswith(".jsbundle"):
                        text = _JS_TEMPLATE_INTERPOLATION_RE.sub("", text)
                    lines.append(f'<string name="ipa_resource">{text}</string>')
        except (zipfile.BadZipFile, OSError):
            return ""
        except Exception:
            return ""

        if not lines:
            return ""
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Service account + private key recovery
    # ------------------------------------------------------------------

    @classmethod
    def extract_service_accounts(
        cls,
        ipa_path: Path,
        parser,
    ) -> List[Dict[str, str]]:
        """Scan every .json file inside an .ipa's app bundle for a
        Firebase service-account credential.

        Mirrors the APK walker. iOS apps don't have a strict assets
        convention like Android, so the walker scans the whole app
        bundle (vs. APKs which only check ``assets/``, ``res/raw/``,
        and root-level JSONs).

        ``parser`` is a callable taking a string and returning either a
        dict with ``client_email`` / ``private_key`` / ``project_id`` or
        ``None``. We accept it as a parameter (instead of importing
        from extractor.py) so this module stays free of cycles.
        """
        service_accounts: List[Dict[str, str]] = []
        seen_emails: set = set()

        try:
            with zipfile.ZipFile(ipa_path) as zf:
                for info in cls._iter_app_files(zf):
                    if not info.filename.lower().endswith(".json"):
                        continue
                    try:
                        with zf.open(info) as fp:
                            raw = fp.read()
                    except Exception:
                        continue
                    try:
                        content = raw.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    sa = parser(content)
                    if sa and sa["client_email"] not in seen_emails:
                        seen_emails.add(sa["client_email"])
                        service_accounts.append(sa)
        except (zipfile.BadZipFile, OSError):
            pass

        return service_accounts

    @classmethod
    def extract_hardcoded_pem_keys(cls, ipa_path: Path) -> List[str]:
        """Recover full PEM private-key blocks hardcoded in the Mach-O.

        Catches the case where a developer pasted a private key directly
        into Swift/Obj-C source instead of bundling a JSON service
        account. The matching ``client_email`` cannot be reconstructed
        from the binary alone (the linker may dedup, reorder, or LTO
        across translation units, so proximity is unreliable), so the
        result is reported as a standalone finding rather than wired
        into the SA auth pipeline.
        """
        binary = cls._read_executable(ipa_path)
        if not binary:
            return []
        keys: List[str] = []
        seen: set = set()
        for match in _PEM_PRIVATE_KEY_RE.finditer(binary):
            try:
                pem = match.group(0).decode("ascii")
            except UnicodeDecodeError:
                continue
            if pem in seen:
                continue
            seen.add(pem)
            keys.append(pem)
        return keys

    # ------------------------------------------------------------------
    # Bundle identifier + executable lookup
    # ------------------------------------------------------------------

    @classmethod
    def extract_bundle_id(cls, ipa_path: Path) -> Optional[str]:
        """Return the CFBundleIdentifier from the app's Info.plist.

        Used as the iOS analogue of an APK's package name — both for
        result keying and for the ``--ios-bundle-id`` API-key bypass.
        """
        try:
            with zipfile.ZipFile(ipa_path) as zf:
                for info in cls._iter_app_files(zf):
                    parts = info.filename.split("/")
                    # Match Payload/<App>.app/Info.plist exactly (not
                    # nested frameworks' Info.plist files).
                    if (
                        len(parts) == 3
                        and parts[0] == "Payload"
                        and parts[1].endswith(".app")
                        and parts[2] == _IOS_INFO_PLIST_NAME
                    ):
                        try:
                            with zf.open(info) as fp:
                                plist = plistlib.load(fp)
                        except (plistlib.InvalidFileException, OSError, ValueError):
                            return None
                        if isinstance(plist, dict):
                            bundle_id = plist.get("CFBundleIdentifier")
                            if isinstance(bundle_id, str) and bundle_id:
                                return bundle_id
                        return None
        except (zipfile.BadZipFile, OSError):
            return None
        except Exception:
            return None
        return None

    @classmethod
    def _read_executable(cls, ipa_path: Path) -> Optional[bytes]:
        """Locate and read the main Mach-O executable from an .ipa.

        The executable name lives in ``Info.plist`` under
        ``CFBundleExecutable``; the file itself sits at
        ``Payload/<App>.app/<CFBundleExecutable>``. Returns the raw
        bytes or ``None`` if the executable cannot be located or
        exceeds :data:`_IOS_BINARY_MAX_BYTES`.
        """
        try:
            with zipfile.ZipFile(ipa_path) as zf:
                app_dir = None
                executable_name = None
                for info in cls._iter_app_files(zf):
                    parts = info.filename.split("/")
                    if (
                        len(parts) == 3
                        and parts[0] == "Payload"
                        and parts[1].endswith(".app")
                        and parts[2] == _IOS_INFO_PLIST_NAME
                    ):
                        try:
                            with zf.open(info) as fp:
                                plist = plistlib.load(fp)
                        except (plistlib.InvalidFileException, OSError, ValueError):
                            return None
                        if isinstance(plist, dict):
                            executable_name = plist.get("CFBundleExecutable")
                            app_dir = f"Payload/{parts[1]}"
                        break

                if not (
                    isinstance(executable_name, str)
                    and executable_name
                    and app_dir
                ):
                    return None

                exe_path = f"{app_dir}/{executable_name}"
                try:
                    exe_info = zf.getinfo(exe_path)
                except KeyError:
                    return None
                if exe_info.file_size > _IOS_BINARY_MAX_BYTES:
                    return None
                with zf.open(exe_info) as fp:
                    return fp.read()
        except (zipfile.BadZipFile, OSError):
            return None
        except Exception:
            return None
