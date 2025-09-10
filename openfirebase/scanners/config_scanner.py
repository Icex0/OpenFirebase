"""Config Scanner for OpenFirebase

Handles Firebase Remote Config scanning functionality.
"""

import os
import time
from typing import Dict, List, Set

import requests

from ..core.config import RED, RESET, YELLOW
from ..utils import is_shutdown_requested
from .base import BaseScanner


class ConfigScanner(BaseScanner):
    """Scans Firebase Remote Config to check accessibility and security status."""

    def scan_project_id(self, project_id: str, config_data: Dict[str, str],
                       package_names: List[str] = None, output_file: str = None) -> Dict[str, str]:
        """Scan a Firebase project ID for Remote Config accessibility.
        
        Args:
            project_id: The Firebase project ID to scan
            config_data: Dictionary containing api_key and app_id for this project
            package_names: List of package names (for file naming)
            output_file: Optional output file to save config responses
            
        Returns:
            Dictionary with scan results for Remote Config URL

        """
        results = {}

        # Extract API key and App ID from config data
        api_key = config_data.get("api_key")
        app_id = config_data.get("app_id")

        if not api_key or not app_id:
            # Create a placeholder result if missing required data
            url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/namespaces/firebase:fetch"
            results[url] = self._build_response_dict(
                status_code=0,
                message="Missing API key or App ID",
                accessible=False,
                security="MISSING_CONFIG",
                response_text="Required configuration data not found in APK. Please check the APK manually."
            )
            return results

        # Firebase Remote Config URL
        url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/namespaces/firebase:fetch?key={api_key}"

        # Extract cert_sha1 and package_name from config_data if available
        cert_sha1 = config_data.get("cert_sha1")
        cert_sha1_list = config_data.get("cert_sha1_list", [])
        package_name = config_data.get("package_name")

        result = self._test_config_url(url, app_id, project_id, package_names, output_file, cert_sha1, package_name, cert_sha1_list)
        results[url] = result

        return results

    def _test_config_url(self, url: str, app_id: str, project_id: str = None,
                        package_names: List[str] = None, output_file: str = None,
                        cert_sha1: str = None, package_name: str = None,
                        cert_sha1_list: List[str] = None) -> Dict[str, str]:
        """Test a Firebase Remote Config URL with POST request.
        
        Args:
            url: The Remote Config URL to test
            app_id: The Google App ID for the POST request
            project_id: The Firebase project ID (for file naming)
            package_names: List of package names (for file naming)
            output_file: Optional output file to save config responses
            cert_sha1: Android app certificate SHA-1 hash (legacy, for backward compatibility)
            package_name: Android app package name
            cert_sha1_list: List of Android certificate SHA-1 hashes to try
            
        Returns:
            Dictionary with scan result

        """
        try:
            # Initialize saved_file_path to ensure it's always defined
            saved_file_path = None

            # Prepare list of certificates to try (prioritize cert_sha1_list, fallback to cert_sha1)
            certificates_to_try = cert_sha1_list or ([cert_sha1] if cert_sha1 else [None])

            # Try each certificate until success or no more certificates
            for cert_index, current_cert_sha1 in enumerate(certificates_to_try):
                # Prepare POST data
                post_data = {
                    "appId": app_id,
                    "appInstanceId": "PROD"
                }

                headers = {
                    "Content-Type": "application/json"
                }

                # Add Android app identification headers if available
                if package_name:
                    headers["X-Android-Package"] = package_name
                if current_cert_sha1:
                    headers["X-Android-Cert"] = current_cert_sha1

                # Make POST request to Firebase Remote Config API
                response = self.session.post(
                    url,
                    json=post_data,
                    headers=headers,
                    timeout=self.timeout
                )

                # Handle the response
                response_text = response.text
                status_code = response.status_code

                # Check if this is an Android restriction error that we should retry with next certificate
                if status_code == 403 and cert_index < len(certificates_to_try) - 1:
                    try:
                        error_data = response.json()
                        error_message = error_data.get("error", {}).get("message", "")
                        if "Android client application" in error_message and "are blocked" in error_message:
                            if current_cert_sha1:
                                print(f"{YELLOW}[CONFIG]{RESET} Android restriction detected with certificate {current_cert_sha1[:8]}..., trying next certificate")
                            else:
                                print(f"{YELLOW}[CONFIG]{RESET} Android restriction detected, trying with certificate...")
                            continue  # Try next certificate
                    except (ValueError, KeyError):
                        pass  # Not JSON or no error message field

                # If we reach here, either success or final failure - break the loop
                break

            # Determine accessibility and security based on status code and response content
            if status_code == 200:
                # Check if the response indicates no template (app doesn't use Remote Config)
                if '"state": "NO_TEMPLATE"' in response_text or '"state":"NO_TEMPLATE"' in response_text:
                    accessible = False
                    security = "NO_CONFIG"
                    message = "No Remote Config template found - app doesn't use Firebase Remote Config"
                else:
                    accessible = True
                    security = "PUBLIC"
                    message = "Remote Config accessible"

                    # Save response content to file when there's actual config data
                    if project_id:
                        # Use project_id as package name if no package names available (e.g., in --project-id mode)
                        effective_package_names = package_names if package_names else [f"project-{project_id}"]
                        saved_file_path = self._save_config_response_to_file(response_text, project_id, effective_package_names, output_file)
            elif status_code in [401, 403]:
                accessible = False
                security = "PROTECTED"
                message = "Access denied"
            elif status_code == 404:
                accessible = False
                security = "NOT_FOUND"
                message = "Remote Config not found"
            elif status_code == 429:
                accessible = False
                security = "RATE_LIMITED"
                message = "Too many requests"
            else:
                accessible = False
                security = "UNKNOWN"
                message = f"HTTP {status_code}"

            response_dict = self._build_response_dict(
                status_code=status_code,
                message=message,
                accessible=accessible,
                security=security,
                response_text=response_text
            )

            # Add saved file path if available
            if saved_file_path:
                response_dict["saved_file_path"] = saved_file_path

            return response_dict

        except requests.exceptions.Timeout:
            return self._build_response_dict(0, "Request timeout", False, "TIMEOUT")
        except requests.exceptions.ConnectionError:
            return self._build_response_dict(0, "Connection error", False, "CONNECTION_ERROR")
        except Exception as e:
            return self._build_response_dict(0, f"Error: {e!s}", False, "ERROR")

    def _save_config_response_to_file(self, response_content: str, project_id: str,
                                    package_names: List[str], output_dir: str = None):
        """Save Remote Config response content to individual files.
        
        Args:
            response_content: The response content from Firebase Remote Config
            project_id: The Firebase project ID
            package_names: List of package names associated with this project (or fallback names)
            output_dir: Directory to save files in (if None, uses "remote_config_results")

        """
        try:
            # Use provided output directory or fall back to default
            if output_dir is None:
                output_dir = "remote_config_results"
            # Extract directory from output file path if it's a file path
            elif output_dir.endswith(".txt"):
                output_dir = os.path.dirname(output_dir)
                if not output_dir:  # If no directory part, use current directory
                    output_dir = "remote_config_results"
                else:
                    output_dir = os.path.join(output_dir, "remote_config_results")
            else:
                output_dir = os.path.join(output_dir, "remote_config_results")

            # Create directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)

            # Create filename with package names for clarity
            if len(package_names) == 1:
                package_part = package_names[0]
            elif len(package_names) > 1:
                package_part = "_".join(package_names)
            else:
                # Fallback if somehow no package names are provided
                package_part = f"project-{project_id}"

            # Replace dots and other special characters that might cause filesystem issues
            safe_package_part = package_part.replace(".", "_").replace("/", "_").replace("\\", "_")

            filename = f"config_{project_id}_{safe_package_part}.txt"
            filepath = os.path.join(output_dir, filename)

            # Save the response content
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"Firebase Remote Config for Project: {project_id}\n")
                # Handle display of package names, showing fallback info if using generated names
                if package_names and package_names[0].startswith("project-"):
                    f.write("Source: Direct project ID scanning (no package info)\n")
                else:
                    f.write(f"Package(s): {', '.join(package_names) if package_names else 'Unknown'}\n")
                f.write("=" * 80 + "\n\n")
                f.write(response_content)

            return filepath

        except Exception as e:
            print(f"   {YELLOW}[!]{RESET}  Warning: Failed to save config response: {e}")
            return None

    def scan_project_ids(self, config_data: Dict[str, Dict[str, str]],
                        package_project_ids: Dict[str, Set[str]] = None,
                        output_file: str = None) -> Dict[str, Dict[str, str]]:
        """Scan Firebase Remote Config for accessibility and security status.
        
        Args:
            config_data: Dictionary mapping project IDs to their config data (api_key, app_id)
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            
        Returns:
            Dictionary mapping project IDs to their scan results

        """
        return self._scan_configs_base(config_data, self.scan_project_id, output_file,
                                     "Remote Config", package_project_ids)

    def scan_config(self, config_data: Dict[str, Dict[str, str]],
                   package_project_ids: Dict[str, Set[str]] = None,
                   output_file: str = None) -> Dict[str, Dict[str, str]]:
        """Scan Firebase Remote Config (alias for scan_project_ids for backward compatibility).
        
        Args:
            config_data: Dictionary mapping project IDs to their config data (api_key, app_id)
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            
        Returns:
            Dictionary mapping project IDs to their scan results

        """
        return self.scan_project_ids(config_data, package_project_ids, output_file)

    def _scan_configs_base(self, config_data: Dict[str, Dict[str, str]], scan_function,
                          output_file: str = None, scan_type: str = "Remote Config Read",
                          package_project_ids: Dict[str, Set[str]] = None) -> Dict[str, Dict[str, str]]:
        """Base method for scanning Remote Config data with rate limiting and file saving.
        
        Args:
            config_data: Dictionary mapping project IDs to their config data
            scan_function: Function to call for scanning each project ID
            output_file: Optional output file to save results gradually
            scan_type: Type of scan (for display purposes)
            package_project_ids: Dictionary mapping package names to sets of project IDs
            
        Returns:
            Dictionary mapping project IDs to their scan results

        """
        results = {}

        # Create reverse mapping from project ID to package names
        project_to_packages = {}
        if package_project_ids:
            for package_name, project_id_set in package_project_ids.items():
                for project_id in project_id_set:
                    if project_id not in project_to_packages:
                        project_to_packages[project_id] = []
                    project_to_packages[project_id].append(package_name)

        # Initialize output file if provided
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"Firebase {scan_type} Scan Results\n")
                f.write("=" * 80 + "\n\n")

        for project_id, project_config_data in sorted(config_data.items()):
            # Check for shutdown request
            if is_shutdown_requested():
                print(f"\n{RED}[X]{RESET} Shutdown requested. Stopping {scan_type.lower()} scan...")
                break

            package_names = project_to_packages.get(project_id, [])

            # Perform scan
            project_results = scan_function(project_id, project_config_data, package_names, output_file)
            results[project_id] = project_results

            # Print results to console (same format as file)
            self._print_project_results(project_id, project_results, package_names)

            # Save results gradually if output file is provided
            if output_file:
                self._save_project_results_to_file(project_id, project_results, output_file, package_names)

            # Rate limiting - sleep between requests
            time.sleep(1.0 / self.rate_limit)

        # Save final summary
        if output_file:
            self._save_final_summary_to_file(results, output_file, "config")

        return results

    def _save_project_results_to_file(self, project_id: str, results: Dict[str, Dict[str, str]],
                                    output_file: str, package_names: List[str] = None):
        """Save individual project results to file."""
        with open(output_file, "a", encoding="utf-8") as f:
            if package_names:
                if len(package_names) == 1:
                    f.write(f"Project ID: {project_id} (from package: {package_names[0]})\n")
                else:
                    f.write(f"Project ID: {project_id} (from packages: {', '.join(package_names)})\n")
            else:
                f.write(f"Project ID: {project_id}\n")
            f.write("=" * 80 + "\n")

            for url, result in results.items():
                status = result.get("status", "unknown")
                security = result.get("security", "unknown")
                message = result.get("message", "No message")

                f.write(f"URL: {url}\n")
                f.write(f"Status: {status}\n")
                f.write(f"Response: {message}\n")

                # Show response content if available
                if "response_content" in result:
                    f.write(f"Content: {result['response_content']}\n")

                status_message = self._get_status_message(status, security, message, result, "config")
                f.write(f"{status_message}\n")
                f.write("\n")

            f.write("\n")

    def _save_final_summary_to_file(self, results: Dict[str, Dict[str, str]], output_file: str, resource_type: str):
        """Save final summary to file."""
        with open(output_file, "a", encoding="utf-8") as f:
            counts = self._count_scan_results(results, resource_type)
            labels = self._get_summary_labels(resource_type)

            f.write("[UNAUTH] SCAN SUMMARY FIREBASE REMOTE CONFIG READ\n")
            f.write("=" * 80 + "\n")
            f.write(f"Total projects scanned: {counts['total_projects']}\n")
            f.write(f"{labels['public']}: {counts['public_count']}\n")
            f.write(f"{labels['protected']}: {counts['protected_count']}\n")
            if resource_type not in ["config", "firestore"]:  # Config and Firestore don't have "not found" status
                f.write(f"{labels['not_found']}: {counts['not_found_count']}\n")

            # Add resource-specific counts
            if resource_type == "config":
                f.write(f"{labels['missing_config']}: {counts['missing_config_count']}\n")
                f.write(f"{labels['no_config']}: {counts['no_config_count']}\n")
            elif resource_type == "database":
                f.write(f"{labels['locked']}: {counts['locked_count']}\n")

            if counts["rate_limited_count"] > 0:
                f.write(f"{labels['rate_limited']}: {counts['rate_limited_count']}\n")
            f.write(f"{labels['other']}: {counts['other_count']}\n")

            if counts["public_count"] > 0:
                if resource_type == "storage":
                    resource_word = "storage buckets"
                elif resource_type == "config":
                    resource_word = "remote configs"
                elif resource_type == "firestore":
                    resource_word = "Firestore databases"
                else:
                    resource_word = "databases"
                f.write(f"\nWARNING: {counts['public_count']} public {resource_word} found!\n")
                f.write(f"These {resource_word} are accessible without authentication.\n")
                # Get the directory where config files are actually saved
                output_dir = os.path.dirname(output_file) if output_file else "."
                config_dir = os.path.join(output_dir, "remote_config_results")
                f.write("It is recommended to scan all configs for secrets with Trufflehog using the following command:\n")
                f.write(f"trufflehog filesystem {config_dir}\n")


