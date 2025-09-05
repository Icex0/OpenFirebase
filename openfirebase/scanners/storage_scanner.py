"""Storage Scanner for OpenFirebase

Handles Firebase Storage bucket scanning functionality.
"""

import os
import time
from typing import Dict, List, Set

import requests

from ..core.config import RED, RESET
from ..utils import is_shutdown_requested
from .base import BaseScanner


class StorageScanner(BaseScanner):
    """Scans Firebase Storage buckets to check accessibility and security status."""

    def scan_project_id(self, project_id: str) -> Dict[str, str]:
        """Scan a Firebase project ID for storage bucket accessibility.

        Args:
            project_id: The Firebase project ID to scan

        Returns:
            Dictionary with scan results for different storage bucket URLs

        """
        results = {}

        # Firebase Storage bucket URLs to test
        urls_to_test = [
            f"https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o",
            f"https://firebasestorage.googleapis.com/v0/b/{project_id}.firebasestorage.app/o",
        ]

        for url in urls_to_test:
            result = self._test_storage_url(url)
            results[url] = result

        return results

    def _test_storage_url(self, url: str) -> Dict[str, str]:
        """Test a specific storage bucket URL and return the result.

        Args:
            url: The storage bucket URL to test

        Returns:
            Dictionary with test results

        """
        try:
            response = self.session.get(url, timeout=self.timeout)

            # Handle common status codes with authentication retry
            common_result = self._handle_common_status_codes_with_auth(response, url, "GET")
            if common_result:
                return common_result

            if response.status_code == 400:
                # Check for specific Firebase Storage rules version error
                if "rules_version" in response.text and "disallowed" in response.text:
                    return self._build_response_dict(
                        400,
                        "Storage rules version 1 - listing disallowed",
                        False,
                        "RULES_VERSION_ERROR",
                        response.text,
                    )
                return self._build_response_dict(
                    400, "Bad request", False, "BAD_REQUEST", response.text
                )

            if response.status_code == 404:
                return self._build_response_dict(
                    404, "Storage bucket not found", False, "NOT_FOUND", response.text
                )

            if response.status_code == 412:
                return self._build_response_dict(
                    412,
                    "A required service account is missing necessary permissions",
                    False,
                    "PERMISSION_ERROR",
                    response.text,
                )

            return self._build_response_dict(
                response.status_code,
                f"HTTP {response.status_code}",
                False,
                "UNKNOWN",
                response.text,
            )

        except requests.exceptions.Timeout:
            return self._build_response_dict(0, "Request timeout", False, "TIMEOUT")
        except requests.exceptions.ConnectionError:
            return self._build_response_dict(
                0, "Connection error", False, "CONNECTION_ERROR"
            )
        except Exception as e:
            return self._build_response_dict(0, f"Error: {e!s}", False, "ERROR")

    def scan_project_ids(
        self,
        project_ids: Set[str],
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
    ) -> Dict[str, Dict[str, str]]:
        """Scan Firebase storage buckets for accessibility and security status.

        Args:
            project_ids: Set of project IDs to scan
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            create_open_only: Whether to create open-only results file (default True)

        Returns:
            Dictionary mapping project IDs to their scan results

        """
        return self._scan_projects_base(
            project_ids,
            self.scan_project_id,
            output_file,
            "Storage Read",
            package_project_ids,
            create_open_only,
        )

    def scan_storage_buckets(
        self,
        project_ids: Set[str],
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
    ) -> Dict[str, Dict[str, str]]:
        """Scan Firebase storage buckets (alias for scan_project_ids for backward compatibility).

        Args:
            project_ids: Set of project IDs to scan
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            create_open_only: Whether to create open-only results file (default True)

        Returns:
            Dictionary mapping project IDs to their scan results

        """
        return self.scan_project_ids(
            project_ids, package_project_ids, output_file, create_open_only
        )

    def write_to_project_id(self, project_id: str, file_path: str) -> Dict[str, str]:
        """Write a file to Firebase Storage bucket for a specific project ID.

        Args:
            project_id: The Firebase project ID to write to
            file_path: Path to the file to upload

        Returns:
            Dictionary with write results for different storage bucket URLs

        """
        if not os.path.exists(file_path):
            return {
                "error": self._build_response_dict(
                    0, f"File not found: {file_path}", False, "FILE_ERROR"
                )
            }

        results = {}

        # Get filename from the file path
        file_name = os.path.basename(file_path)

        # Firebase Storage bucket URLs to test (similar to read operations)
        urls_to_test = [
            f"https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o?name={file_name}",
            f"https://firebasestorage.googleapis.com/v0/b/{project_id}.firebasestorage.app/o?name={file_name}",
        ]

        for url in urls_to_test:
            result = self._test_storage_write_url(url, file_path)
            results[url] = result

        return results

    def _test_storage_write_url(self, url: str, file_path: str) -> Dict[str, str]:
        """Test write access to a specific storage bucket URL.

        Args:
            url: The storage bucket URL to test write access
            file_path: Path to the file to upload

        Returns:
            Dictionary with write results

        """
        try:
            # Read file content for upload
            with open(file_path, encoding="utf-8") as f:
                file_content = f.read()

            # Prepare headers for text file upload
            headers = {"Content-Type": "text/plain"}

            # Make POST request to upload file
            response = self.session.post(
                url, data=file_content, headers=headers, timeout=self.timeout
            )

            # Handle common status codes with auth retry support
            common_result = self._handle_common_status_codes_with_auth(
                response, url, method="POST", data=file_content, headers=headers
            )
            if common_result:
                # For storage write operations, update the message to be more specific
                if response.status_code == 200:
                    common_result["message"] = (
                        "File upload successful - write access allowed"
                    )
                return common_result

            if response.status_code == 400:
                # Check for specific Firebase Storage errors
                response_text = response.text.lower()
                if "invalid" in response_text and "name" in response_text:
                    return self._build_response_dict(
                        400,
                        "Invalid file name format",
                        False,
                        "INVALID_NAME",
                        response.text,
                    )
                if "permission" in response_text or "denied" in response_text:
                    return self._build_response_dict(
                        400,
                        "Write permission denied",
                        False,
                        "WRITE_DENIED",
                        response.text,
                    )
                return self._build_response_dict(
                    400, "Bad request", False, "BAD_REQUEST", response.text
                )



            if response.status_code == 404:
                return self._build_response_dict(
                    404, "Storage bucket not found", False, "NOT_FOUND", response.text
                )

            if response.status_code == 412:
                return self._build_response_dict(
                    412,
                    "Write precondition failed",
                    False,
                    "WRITE_PRECONDITION_FAILED",
                    response.text,
                )

            return self._build_response_dict(
                response.status_code,
                f"HTTP {response.status_code}",
                False,
                "UNKNOWN",
                response.text,
            )

        except requests.exceptions.Timeout:
            return self._build_response_dict(0, "Request timeout", False, "TIMEOUT")
        except requests.exceptions.ConnectionError:
            return self._build_response_dict(
                0, "Connection error", False, "CONNECTION_ERROR"
            )
        except OSError as e:
            return self._build_response_dict(
                0, f"File read error: {e!s}", False, "FILE_ERROR"
            )
        except Exception as e:
            return self._build_response_dict(0, f"Error: {e!s}", False, "ERROR")

    def write_to_project_ids(
        self,
        project_ids: Set[str],
        file_path: str,
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
    ) -> Dict[str, Dict[str, str]]:
        """Write to Firebase storage buckets for multiple project IDs.

        Args:
            project_ids: Set of project IDs to write to
            file_path: Path to the file to upload
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            create_open_only: Whether to create open-only results file (default True)

        Returns:
            Dictionary mapping project IDs to their write results

        """
        return self._scan_projects_base(
            project_ids,
            lambda pid: self.write_to_project_id(pid, file_path),
            output_file,
            "Storage Write",
            package_project_ids,
            create_open_only,
        )

    def _scan_projects_base(
        self,
        project_ids: Set[str],
        scan_function,
        output_file: str = None,
        scan_type: str = "Storage Read",
        package_project_ids: Dict[str, Set[str]] = None,
        create_open_only: bool = True,
    ) -> Dict[str, Dict[str, str]]:
        """Base method for scanning multiple project IDs with rate limiting and file saving.

        Args:
            project_ids: Set of project IDs to scan
            scan_function: Function to call for scanning each project ID
            output_file: Optional output file to save results gradually
            scan_type: Type of scan (for display purposes)
            package_project_ids: Dictionary mapping package names to sets of project IDs
            create_open_only: Whether to create open-only results file

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

        for project_id in sorted(project_ids):
            # Check for shutdown request
            if is_shutdown_requested():
                print(f"\n{RED}[X]{RESET} Shutdown requested. Stopping {scan_type.lower()} scan...")
                break

            # Perform scan
            project_results = scan_function(project_id)
            results[project_id] = project_results

            package_names = project_to_packages.get(project_id, [])

            # Print results to console (same format as file)
            self._print_project_results(project_id, project_results, package_names)

            # Save results gradually if output file is provided
            if output_file:
                self._save_project_results_to_file(
                    project_id, project_results, output_file, package_names
                )
                # Save authenticated results to file (before they're cleared)
                if project_id in self.all_authenticated_results:
                    self._save_authenticated_results_to_file_for_project(
                        project_id, output_file
                    )

            # Rate limiting - sleep between requests
            time.sleep(1.0 / self.rate_limit)

        # Save final summary
        if output_file:
            self._save_final_summary_to_file(results, output_file, "storage")

            # Create open-only results file if requested (for single scans)
            if create_open_only:
                self._save_open_only_results(
                    results, output_file, "storage", package_project_ids
                )

        return results

    def _save_project_results_to_file(
        self,
        project_id: str,
        results: Dict[str, Dict[str, str]],
        output_file: str,
        package_names: List[str] = None,
    ):
        """Save individual project results to file."""
        with open(output_file, "a", encoding="utf-8") as f:
            if package_names:
                if len(package_names) == 1:
                    f.write(
                        f"Project ID: {project_id} (from package: {package_names[0]})\n"
                    )
                else:
                    f.write(
                        f"Project ID: {project_id} (from packages: {', '.join(package_names)})\n"
                    )
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

                status_message = self._get_status_message(
                    status, security, message, result, "storage"
                )
                f.write(f"{status_message}\n")
                f.write("\n")

            f.write("\n")

    def _save_final_summary_to_file(
        self, results: Dict[str, Dict[str, str]], output_file: str, resource_type: str
    ):
        """Save final summary to file."""
        with open(output_file, "a", encoding="utf-8") as f:
            counts = self._count_scan_results(results, resource_type)
            labels = self._get_summary_labels(resource_type)

            f.write("[UNAUTH] SCAN SUMMARY FIREBASE STORAGE READ\n")
            f.write("=" * 80 + "\n")
            f.write(f"Total projects scanned: {counts['total_projects']}\n")
            f.write(f"{labels['public']}: {counts['public_count']}\n")
            f.write(f"{labels['protected']}: {counts['protected_count']}\n")
            if resource_type not in [
                "config",
                "firestore",
            ]:  # Config and Firestore don't have "not found" status
                f.write(f"{labels['not_found']}: {counts['not_found_count']}\n")

            # Add resource-specific counts
            if resource_type == "config":
                f.write(
                    f"{labels['missing_config']}: {counts['missing_config_count']}\n"
                )
                f.write(f"{labels['no_config']}: {counts['no_config_count']}\n")
            elif resource_type == "database":
                f.write(f"{labels['locked']}: {counts['locked_count']}\n")
            elif resource_type == "storage":
                f.write(f"{labels['no_listing']}: {counts['no_listing_count']}\n")

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
                f.write(
                    f"\nWARNING: {counts['public_count']} public {resource_word} found!\n"
                )
                f.write(
                    f"These {resource_word} are accessible without authentication.\n"
                )
