"""APK Signature Extractor Module

This module contains the SignatureExtractor class that handles
extracting SHA-1 certificate hashes and package names from APK files.
"""

import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

import requests


class SignatureExtractor:
    """Extracts signature and package information from APK files."""

    @staticmethod
    def setup_apksigner() -> Optional[Path]:
        """Download and setup apksigner.jar if not already available.
        
        Returns:
            Path to apksigner.jar if successful, None otherwise

        """
        # Import colors from config
        from ..core.config import BLUE, RED, RESET

        # Install in OpenFirebase tools directory
        package_dir = Path(__file__).parent.parent  # openfirebase/ directory
        tools_dir = package_dir / "tools"
        apksigner_path = tools_dir / "apksigner.jar"

        # Check if apksigner.jar already exists
        if apksigner_path.exists():
            return apksigner_path

        print(f"{BLUE}[INF]{RESET} Setting up apksigner.jar for APK signature extraction...")

        try:
            # Create tools directory
            tools_dir.mkdir(exist_ok=True)

            # Download build-tools
            from ..core.config import (
                ANDROID_BUILD_TOOLS_FOLDER,
                ANDROID_BUILD_TOOLS_URL,
            )
            url = ANDROID_BUILD_TOOLS_URL
            zip_path = tools_dir / "build-tools.zip"

            print(f"{BLUE}[INF]{RESET} Downloading Android build tools from {url}...")
            response = requests.get(url, stream=True)
            response.raise_for_status()

            with open(zip_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Extract the zip file
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(tools_dir)

            # Find and copy apksigner.jar from the extracted files
            extracted_dir = tools_dir / ANDROID_BUILD_TOOLS_FOLDER
            lib_dir = extracted_dir / "lib"
            source_apksigner = lib_dir / "apksigner.jar"

            if source_apksigner.exists():
                # Copy apksigner.jar to tools directory
                shutil.copy2(source_apksigner, apksigner_path)
                print(f"{BLUE}[INF]{RESET} apksigner.jar extracted successfully")
            else:
                print(f"{RED}[ERROR]{RESET} apksigner.jar not found in extracted files")
                return None

            # Clean up downloaded files
            zip_path.unlink()
            shutil.rmtree(extracted_dir)

            return apksigner_path

        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to setup apksigner.jar: {e}")
            return None

    @staticmethod
    def extract_apk_signature(apk_path: Path) -> Tuple[List[str], Optional[str]]:
        """Extract SHA-1 certificate hashes and package name from APK file.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Tuple of (sha1_hashes_list, package_name) where sha1_hashes_list contains all certificates

        """
        # Import colors from config
        from ..core.config import RED, RESET
        # Setup apksigner if needed
        apksigner_path = SignatureExtractor.setup_apksigner()
        if not apksigner_path:
            return [], None

        try:
            # Extract all SHA-1 hashes using apksigner
            sha1_hashes = []
            result = subprocess.run([
                "java", "-jar", str(apksigner_path), "verify", "--print-certs", str(apk_path)
            ], check=False, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                # Parse the output to extract all SHA-1 hashes from regular Signer sections only (not Source Stamp Signer)
                for line in result.stdout.split("\n"):
                    line = line.strip()

                    # Extract SHA-1 from both formats:
                    # Format 1: "Signer (minSdkVersion=...) certificate SHA-1 digest: ..."
                    # Format 2: "Signer #1 certificate SHA-1 digest: ..."
                    # But exclude "Source Stamp Signer certificate SHA-1 digest: ..."
                    if "certificate SHA-1 digest:" in line:
                        # Check if it's a regular signer (not Source Stamp Signer)
                        if (line.startswith("Signer (") or
                            line.startswith("Signer #")) and not line.startswith("Source Stamp Signer"):
                            sha1_hash = line.split(":")[-1].strip()
                            if sha1_hash:  # Only add non-empty hashes
                                sha1_hashes.append(sha1_hash)

            # Extract package name using androguard (primary method)
            package_name = None
            try:
                # Try using androguard APK.get_package() first
                from androguard.core.apk import APK
                apk = APK(apk_path)
                package_name = apk.get_package()
            except Exception:
                # If androguard fails, fall back to APK filename
                package_name = apk_path.stem

            return sha1_hashes, package_name

        except subprocess.TimeoutExpired:
            print(f"{RED}[ERROR]{RESET} Timeout while extracting signature from {apk_path.name}")
            return [], None
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to extract signature from {apk_path.name}: {e}")
            return [], None
