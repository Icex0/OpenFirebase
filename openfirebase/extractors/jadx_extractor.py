"""JADX Extractor Module

This module contains the JADXExtractor class that handles
decompiling APK files using JADX and searching for Firebase patterns.
"""

import io
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.request import urlopen
from zipfile import ZipFile

from tqdm import tqdm

from ..core.config import (
    BLUE,
    DEFAULT_TIMEOUT_SECONDS,
    FILTERED_COLLECTION_VALUES,
    FILTERED_DOMAINS,
    JADX_DOWNLOAD_URL,
    JADX_VERSION,
    LIME,
    RED,
    RESET,
    YELLOW,
)
from ..parsers.pattern_loader import get_firebase_patterns, get_pattern_metadata
from ..utils import is_shutdown_requested


class JADXExtractor:
    """Extracts Firebase items from APK files by decompiling with JADX and searching source code."""

    @property
    def FIREBASE_PATTERNS(self) -> Dict[str, str]:
        """Get Firebase patterns from centralized configuration."""
        return get_firebase_patterns()

    def __init__(
        self,
        input_folder: str,
        auto_install: bool = False,
        processing_mode: str = "directory",
        timeout_seconds: int = None,
    ):
        """Initialize the extractor with the input folder path."""
        self.input_folder = Path(input_folder)
        self.results: Dict[str, List[Tuple[str, str]]] = {}
        self.results_lock = threading.Lock()  # Thread-safe access to results
        self.main_dir = os.path.dirname(os.path.realpath(__file__))
        self.processing_mode = processing_mode  # "single" or "directory"
        self.timeout_seconds = timeout_seconds if timeout_seconds is not None else DEFAULT_TIMEOUT_SECONDS

        # Determine JADX path (system or local)
        self.jadx_path = self._get_jadx_path()

        # Check if JADX is available and offer to install if not
        self.jadx_available = self._check_jadx_integrity(auto_install=auto_install)

    def _get_jadx_path(self) -> str:
        """Get JADX executable path, preferring system installation."""
        # Check if JADX is in PATH
        system_jadx = shutil.which("jadx")
        if system_jadx:
            return system_jadx

        # Fallback to local installation path in tools directory (within package)
        package_dir = Path(self.main_dir).parent  # openfirebase/ directory
        tools_dir = package_dir / "tools" / "jadx" / "bin"
        if os.name == "nt":  # Windows
            return str(tools_dir / "jadx.bat").replace("\\", "/")
        # Unix-like systems
        return str(tools_dir / "jadx").replace("\\", "/")

    def _check_jadx_availability(self) -> bool:
        """Check if JADX is available at the specified path."""
        try:
            result = subprocess.run(
                [self.jadx_path, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _download_jadx(self) -> bool:
        """Download and install JADX from GitHub releases."""
        jadx_url = JADX_DOWNLOAD_URL
        # Install in tools directory for consistency with other tools
        package_dir = Path(self.main_dir).parent  # openfirebase/ directory
        install_dir = str(package_dir / "tools" / "jadx")

        try:
            print(f"{BLUE}[INF]{RESET} Downloading JADX v{JADX_VERSION}...")
            with closing(urlopen(jadx_url)) as response:
                with ZipFile(io.BytesIO(response.read())) as zfile:
                    # Create install directory if it doesn't exist
                    os.makedirs(install_dir, exist_ok=True)
                    # Extract JADX
                    zfile.extractall(install_dir)

            # Set executable permissions on Unix-like systems
            if os.name != "nt":
                jadx_bin = os.path.join(install_dir, "bin", "jadx")
                if os.path.exists(jadx_bin):
                    os.chmod(jadx_bin, 0o755)  # rwxr-xr-x

            print(f"{LIME}[+]{RESET} JADX installation completed successfully!")
            return True

        except Exception as error:
            print(f"{RED}[X]{RESET} Error downloading JADX: {error!s}")
            return False

    def _check_jadx_integrity(self, auto_install: bool = False) -> bool:
        """Check JADX integrity and offer to download if missing."""
        if self._check_jadx_availability():
            return True

        print(f"{YELLOW}[!]{RESET}  JADX not found.")

        if auto_install:
            print(f"🔧 Auto-installing JADX v{JADX_VERSION}...")
            success = self._download_jadx()
            if success:
                self.jadx_path = self._get_jadx_path()
                return self._check_jadx_availability()
            return False

        # Prompt user for installation
        valid_responses = {"yes": True, "y": True, "ye": True, "no": False, "n": False}

        while True:
            try:
                response = (
                    input(f"{BLUE}[INF]{RESET} Do you want to download and install JADX v{JADX_VERSION}? (Y/n): ")
                    .lower()
                    .strip()
                )

                if response == "":
                    response = "y"

                if response in valid_responses:
                    choice = valid_responses[response]
                    break
                print("Please respond with 'yes' or 'no' (or 'y' or 'n').")

            except KeyboardInterrupt:
                print("\n⛔ Installation cancelled by user.")
                return False

        if choice:
            success = self._download_jadx()
            if success:
                # Update jadx_path to the newly installed version
                self.jadx_path = self._get_jadx_path()
                return self._check_jadx_availability()
            return False
        print("⛔ JADX installation skipped. JADX decompilation will not be available.")
        return False



    def _cleanup_temp_directory(self, temp_dir: str) -> None:
        """Robustly clean up temporary directory, handling files that might be in use.

        Args:
            temp_dir: Path to temporary directory to clean up

        """
        # Skip cleanup during graceful shutdown to avoid locked file issues
        if is_shutdown_requested():
            return
            
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                # First, try to remove read-only attributes on Windows
                if os.name == "nt":  # Windows
                    for root, _, files in os.walk(temp_dir):
                        for name in files:
                            file_path = os.path.join(root, name)
                            try:
                                os.chmod(file_path, 0o777)
                            except:
                                pass

                # Try to remove the directory
                shutil.rmtree(temp_dir, ignore_errors=False)
                break  # Success, exit loop

            except OSError as e:
                if attempt < max_attempts - 1:
                    # Wait a bit and try again
                    print(
                        f"{BLUE}[INF]{RESET} Cleanup attempt {attempt + 1} failed, retrying in 1 second..."
                    )
                    time.sleep(1)
                else:
                    # Final attempt failed
                    try:
                        # Try force removal on Unix-like systems
                        if os.name != "nt":
                            import subprocess

                            subprocess.run(
                                ["rm", "-rf", temp_dir],
                                check=False,
                                capture_output=True,
                                timeout=10,
                            )
                        else:
                            print(
                                f"  {YELLOW}[!]{RESET}  Warning: Could not clean up temp directory {temp_dir}: {e}"
                            )
                    except:
                        print(
                            f"  {YELLOW}[!]{RESET}  Warning: Could not clean up temp directory {temp_dir}: {e}"
                        )

    def _decompile_apk(self, apk_path: Path, output_dir: Path) -> Tuple[bool, bool]:
        """Decompile APK using JADX with user prompt on timeout.
        
        Returns:
            Tuple[bool, bool]: (success, timeout_occurred)

        """
        if not self.jadx_available:
            print(f"  {RED}[X]{RESET} JADX not available for decompiling {apk_path.name}")
            return False, False

        # JADX command: jadx apk_path -d output_dir
        cmd = [self.jadx_path, str(apk_path), "-d", str(output_dir)]

        # Start the process
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Wait for configured timeout initially
            try:
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)

                # Check if output directory actually contains files (more reliable than exit code)
                output_files = list(output_dir.rglob("*"))

                if len(output_files) > 0:
                    return True, False
                return False, False

            except subprocess.TimeoutExpired:
                # Process exceeded timeout - terminate automatically
                process_pid = process.pid
                timeout_minutes = self.timeout_seconds // 60
                print(f"\n{BLUE}[INF]{RESET} Decompilation of {apk_path.name} exceeded {timeout_minutes}-minute timeout (PID: {process_pid})")
                print(f"{BLUE}[INF]{RESET} Terminating decompilation process (PID: {process_pid})")

                process.terminate()
                try:
                    process.wait(timeout=5)
                    print(f"{BLUE}[INF]{RESET} Process terminated gracefully")
                except subprocess.TimeoutExpired:
                    print(f"{BLUE}[INF]{RESET} Force killing process (PID: {process_pid})")
                    process.kill()
                    process.wait()
                    print(f"{BLUE}[INF]{RESET} Process killed")

                print(f"{BLUE}[INF]{RESET} Falling back to fast extraction method...")
                return False, True  # Indicate timeout occurred

        except Exception as e:
            print(f"  {RED}[X]{RESET} Error decompiling {apk_path.name}: {e}")
            return False, False

    def _fallback_to_fast_extraction(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Fallback to fast extraction when JADX times out."""
        try:
            from ..extractors.extractor import FirebaseExtractor

            print(f"{BLUE}[INF]{RESET} Using fast extraction fallback for {apk_path.name}")
            print(f"{YELLOW}[WARNING]{RESET} Firebase items in the source code, such as Firestore collections will not be detected!")

            # Create fast extractor and process the APK
            fast_extractor = FirebaseExtractor(apk_path.parent)
            firebase_items = fast_extractor.extract_from_apk(apk_path)

            if firebase_items:
                print(f"{BLUE}[INF]{RESET} Fast extraction found {len(firebase_items)} Firebase items")
            else:
                print(f"{YELLOW}[!]{RESET} Fast extraction found no Firebase items")

            return firebase_items

        except Exception as e:
            print(f"  {RED}[X]{RESET} Error in fast extraction fallback for {apk_path.name}: {e}")
            return []

    def _search_files_recursive(
        self, directory: Path, _: List[str] = None
    ) -> List[Path]:
        """Recursively find files with specified extensions, optimized for Firebase patterns."""
        files = []
        try:
            # Java files - contain Firestore patterns and Firebase URLs
            files.extend(directory.rglob("*.java"))

            # XML files - only from /res/values directories (contains strings.xml and other Firebase config)
            xml_files = directory.rglob("*.xml")
            for xml_file in xml_files:
                path_str = str(xml_file).lower()
                if "/res/values" in path_str:
                    files.append(xml_file)

            # JSON files - may contain Firebase URLs in some cases
            files.extend(directory.rglob("*.json"))

        except Exception as e:
            print(f"Error searching files in {directory}: {e}")

        return files

    def _should_skip_firebase_example_domains(self, link: str) -> bool:
        """Check if link should be skipped due to example/test domains."""
        return any(skip_term in link.lower() for skip_term in FILTERED_DOMAINS)

    def _should_skip_firestore_code_patterns(self, header: str, link: str) -> bool:
        """Check if Firestore link should be skipped due to code-like patterns."""
        if not header.startswith("Firestore_"):
            return False

        link_clean = link.strip()

        # Skip if it looks like code concatenation (contains operators with spaces)
        if any(op in link for op in [" + ", " - ", " * ", " / ", " & ", " | ", " = "]):
            return True

        # Skip if it starts or ends with common code artifacts
        code_chars = (
            "+", "-", "_", "*", "/", "&", "|", "=", ",", ";",
            "(", ")", "[", "]", "{", "}", ".", "<", ">"
        )
        if link_clean.startswith(code_chars) or link_clean.endswith(code_chars):
            return True

        # Skip common code keywords and method-like patterns
        if (link_clean.lower() in ["this", "self", "that", "null", "true", "false", "void"]
            or "valueOf" in link_clean
            or "toString" in link_clean
            or "getString" in link_clean):
            return True

        # Skip very generic single character or short patterns
        if len(link_clean) <= 2 or link_clean.isdigit():
            return True

        # Skip if it contains multiple consecutive special characters (likely code fragment)
        if any(char1 + char2 in link
               for char1 in ",;()[]{}."
               for char2 in ",;()[]{}."
               if char1 != char2):
            return True

        return False

    def _process_file_content(self, content: str, seen_links: set) -> Tuple[List[Tuple[str, str]], int]:
        """Process file content and extract Firebase patterns."""
        firebase_items = []
        file_matches = 0

        # Get pattern metadata for capture group information
        pattern_metadata = get_pattern_metadata()

        # Search for Firebase patterns
        for header, pattern in self.FIREBASE_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Use capture group information from configuration
                pattern_info = pattern_metadata.get(header, {})
                capture_group = pattern_info.get("capture_group", 0)

                if (capture_group == 1 and match.groups() and len(match.groups()) > 0):
                    link = match.group(1)  # Get the captured value from group 1
                else:
                    link = match.group(0)  # Get the full match

                # Clean up the link
                link = link.strip("'\"()<>[]{}")

                # Skip empty or very short matches
                if len(link) < 3:
                    continue

                # Filter out Firebase example/test domains and placeholder IDs
                if self._should_skip_firebase_example_domains(link):
                    continue

                # Filter out code-like patterns for Firestore names
                if self._should_skip_firestore_code_patterns(header, link):
                    continue

                # Filter out collection values that are in the filtered list
                if "Collection" in header:
                    if link.lower() in [value.lower() for value in FILTERED_COLLECTION_VALUES]:
                        continue

                # Only add if we haven't seen this exact link before
                if link not in seen_links:
                    firebase_items.append((header, link))
                    seen_links.add(link)
                    file_matches += 1

        return firebase_items, file_matches

    def _extract_from_decompiled_code(
        self, decompiled_dir: Path
    ) -> List[Tuple[str, str]]:
        """Extract Firebase patterns from decompiled code."""
        firebase_items = []
        seen_links = set()  # Track seen links to avoid duplicates

        # Find all relevant files
        files_to_search = self._search_files_recursive(decompiled_dir)

        if not files_to_search:
            return firebase_items

        # Process files without progress bar to avoid conflicts
        for file_path in files_to_search:
            # Check for shutdown request
            if is_shutdown_requested():
                print(f"\n{RED}[X]{RESET} File scanning aborted by user")
                break

            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                file_items, file_matches = self._process_file_content(content, seen_links)
                firebase_items.extend(file_items)

            except Exception:
                # Skip files that can't be read
                pass

        # Remove print statement - will be handled by main progress bar

        return firebase_items

    def extract_from_apk(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Extract Firebase items from a single APK file using JADX decompilation."""
        if not self.jadx_available:
            return []

        firebase_items = []
        temp_dir = None

        try:
            # Create temporary directory for decompilation
            temp_dir = tempfile.mkdtemp(prefix=f"jadx_{apk_path.stem}_")
            temp_path = Path(temp_dir)

            # Decompile APK
            success, timeout_occurred = self._decompile_apk(apk_path, temp_path)

            if success:
                # Search for Firebase patterns in decompiled code
                firebase_items = self._extract_from_decompiled_code(temp_path)
            elif timeout_occurred:
                # Fallback to fast extraction when JADX times out
                firebase_items = self._fallback_to_fast_extraction(apk_path)

        except Exception as e:
            print(f"  {RED}[X]{RESET} Error processing {apk_path.name}: {e}")

        finally:
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                self._cleanup_temp_directory(temp_dir)

        # Extract APK signature and package name for Remote Config
        from .signature_extractor import SignatureExtractor
        cert_sha1_list, apk_package_name = SignatureExtractor.extract_apk_signature(apk_path)

        # Add all SHA-1 certificate information to Firebase items
        for cert_sha1 in cert_sha1_list:
            firebase_items.append(("APK_Certificate_SHA1", cert_sha1))
        if apk_package_name:
            firebase_items.append(("APK_Package_Name", apk_package_name))

        return firebase_items

    def extract_from_apk_with_progress(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Extract Firebase items from a single APK file using JADX decompilation with progress bar."""
        if not self.jadx_available:
            return []

        firebase_items = []
        temp_dir = None

        try:
            # Create temporary directory for decompilation
            temp_dir = tempfile.mkdtemp(prefix=f"jadx_{apk_path.stem}_")
            temp_path = Path(temp_dir)

            print(f"{BLUE}[INF]{RESET} Decompiling APK with JADX...")
            # Decompile APK
            success, timeout_occurred = self._decompile_apk(apk_path, temp_path)

            if success:
                print(
                    f"{BLUE}[INF]{RESET} Scanning decompiled files for Firebase patterns..."
                )
                # Search for Firebase patterns in decompiled code with progress
                firebase_items = self._extract_from_decompiled_code_with_progress(
                    temp_path
                )
            elif timeout_occurred:
                # Fallback to fast extraction when JADX times out
                firebase_items = self._fallback_to_fast_extraction(apk_path)

        except Exception as e:
            print(f"  {RED}[X]{RESET} Error processing {apk_path.name}: {e}")

        finally:
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                self._cleanup_temp_directory(temp_dir)

        # Extract APK signature and package name for Remote Config
        from .signature_extractor import SignatureExtractor
        cert_sha1_list, apk_package_name = SignatureExtractor.extract_apk_signature(apk_path)

        # Add all SHA-1 certificate information to Firebase items
        for cert_sha1 in cert_sha1_list:
            firebase_items.append(("APK_Certificate_SHA1", cert_sha1))
        if apk_package_name:
            firebase_items.append(("APK_Package_Name", apk_package_name))

        return firebase_items

    def _extract_from_decompiled_code_with_progress(
        self, decompiled_dir: Path
    ) -> List[Tuple[str, str]]:
        """Extract Firebase patterns from decompiled code with progress bar."""
        firebase_items = []
        seen_links = set()  # Track seen links to avoid duplicates

        # Find all relevant files
        files_to_search = self._search_files_recursive(decompiled_dir)

        if not files_to_search:
            return firebase_items

        # Process files with progress bar
        with tqdm(
            total=len(files_to_search), desc="Scanning files", unit="file", leave=True
        ) as pbar:
            for file_path in files_to_search:
                # Check for shutdown request
                if is_shutdown_requested():
                    print(f"\n{RED}[X]{RESET} File scanning aborted by user")
                    break

                try:
                    with open(file_path, encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    file_items, file_matches = self._process_file_content(content, seen_links)
                    firebase_items.extend(file_items)

                except Exception:
                    # Skip files that can't be read
                    pass

                pbar.update(1)

        return firebase_items

    def get_apk_files(self) -> List[Path]:
        """Get all APK files from the input folder."""
        from ..utils import get_apk_files
        return get_apk_files(self.input_folder)

    def process_file(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Process a single APK file and return Firebase items."""
        firebase_items = self.extract_from_apk(apk_path)

        # Extract real package name
        from ..utils import get_apk_package_name
        package_name = get_apk_package_name(apk_path)

        if firebase_items:
            with self.results_lock:
                self.results[package_name] = firebase_items
                
        return firebase_items

    def process_file_with_progress(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Process a single APK file with progress bar showing file scanning progress."""
        firebase_items = self.extract_from_apk_with_progress(apk_path)

        # Extract real package name
        from ..utils import get_apk_package_name
        package_name = get_apk_package_name(apk_path)

        if firebase_items:
            with self.results_lock:
                self.results[package_name] = firebase_items

        return firebase_items

    def get_results(self) -> Dict[str, List[Tuple[str, str]]]:
        """Get the current results."""
        return self.results.copy()
