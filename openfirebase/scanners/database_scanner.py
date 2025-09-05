"""Database Scanner for OpenFirebase

Handles Firebase Realtime Database scanning functionality.
"""

import re
import time
from typing import Dict, List, Set

import requests

from ..core.config import RED, RESET
from ..utils import is_shutdown_requested
from .base import BaseScanner


class DatabaseScanner(BaseScanner):
    """Scans Firebase Realtime Databases to check accessibility and security status."""

    def scan_project_id(self, project_id: str) -> Dict[str, str]:
        """Scan a Firebase project ID to check database accessibility.

        Args:
            project_id: The Firebase project ID to scan

        Returns:
            Dictionary with scan results for different database URLs

        """
        results = {}

        # Standard Firebase Realtime Database URLs to test
        urls_to_test = [
            f"https://{project_id}.firebaseio.com/.json",
            f"https://{project_id}-default-rtdb.firebaseio.com/.json",
        ]

        for url in urls_to_test:
            result = self._test_database_url(url)
            results[url] = result

            # If we get a region redirect, follow it
            if result["status"] == "404" and "region_redirect" in result:
                redirect_url = result["region_redirect"]
                redirect_result = self._test_database_url(redirect_url)
                results[redirect_url] = redirect_result

        return results

    def _test_database_url(self, url: str) -> Dict[str, str]:
        """Test a specific database URL and return the result.

        Args:
            url: The database URL to test

        Returns:
            Dictionary with test results

        """
        try:
            response = self.session.get(url, timeout=self.timeout)

            # Handle common status codes with authentication retry
            common_result = self._handle_common_status_codes_with_auth(response, url, "GET")
            if common_result:
                return common_result

            if response.status_code == 404:
                content = response.text.lower()

                # Check for Firebase error message indicating incorrect URL
                if "firebase error" in content and "configured correctly" in content:
                    return self._build_response_dict(
                        404,
                        "Database not found",
                        False,
                        "PRIVATE",
                        response.text,
                    )

                # Check for region redirect message
                region_match = re.search(
                    r'https://[^"]+\.firebasedatabase\.app', response.text
                )
                if region_match:
                    region_url = region_match.group(0) + "/.json"
                    return self._build_response_dict(
                        404,
                        "Database lives in different region",
                        False,
                        "REGION_REDIRECT",
                        response.text,
                        region_redirect=region_url,
                    )

                # Check for locked/deactivated database
                if "locked" in content or "deactivated" in content:
                    return self._build_response_dict(
                        423,
                        "Database locked/deactivated",
                        False,
                        "LOCKED",
                        response.text,
                    )

                return self._build_response_dict(
                    404, "Database not found", False, "NOT_FOUND", response.text
                )

            if response.status_code == 423:
                return self._build_response_dict(
                    423, "Database locked/deactivated", False, "LOCKED", response.text
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
        """Scan multiple project IDs with rate limiting and gradual file saving.

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
            "Database",
            package_project_ids,
            create_open_only,
        )

    def scan_databases(
        self,
        project_ids: Set[str],
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
    ) -> Dict[str, Dict[str, str]]:
        """Scan Firebase databases (alias for scan_project_ids for backward compatibility).

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

    def _scan_projects_base(
        self,
        project_ids: Set[str],
        scan_function,
        output_file: str = None,
        scan_type: str = "Database Read",
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
            self._save_final_summary_to_file(results, output_file, scan_type.lower())

            # Create open-only results file if requested (for single scans)
            if create_open_only:
                self._save_open_only_results(
                    results, output_file, scan_type.lower(), package_project_ids
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
                    status, security, message, result, "database"
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

            f.write("[UNAUTH] SCAN SUMMARY FIREBASE REALTIME DATABASE READ\n")
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

    # Write methods for RTDB
    def write_to_project_id(self, project_id: str, json_file_path: str) -> Dict[str, str]:
        """Write to Firebase Realtime Database for a specific project ID.

        Args:
            project_id: The Firebase project ID to test write access
            json_file_path: Path to JSON file containing data to write

        Returns:
            Dictionary mapping URLs to their write results

        """
        results = {}

        # Read JSON data from file
        try:
            import json
            with open(json_file_path, encoding="utf-8") as f:
                json_data = json.load(f)
        except Exception as e:
            # Return error for all URLs if we can't read the file
            error_result = self._build_response_dict(0, f"Failed to read JSON file: {e!s}", False, "FILE_ERROR")
            return {
                f"https://{project_id}.firebaseio.com/openfirebase-unauth-check.json": error_result,
                f"https://{project_id}-default-rtdb.firebaseio.com/openfirebase-unauth-check.json": error_result,
            }

        # Standard Firebase Realtime Database URLs to test for write access
        urls_to_test = [
            f"https://{project_id}.firebaseio.com/openfirebase-unauth-check.json",
            f"https://{project_id}-default-rtdb.firebaseio.com/openfirebase-unauth-check.json",
        ]

        for url in urls_to_test:
            result = self._test_database_write_url(url, json_data)
            results[url] = result

            # If we get a region redirect, follow it
            if result["status"] == "404" and "region_redirect" in result:
                redirect_url = result["region_redirect"]
                # Convert redirect URL to write URL format
                if redirect_url.endswith("/.json"):
                    redirect_write_url = redirect_url[:-6] + "/openfirebase-unauth-check.json"
                else:
                    redirect_write_url = redirect_url + "/openfirebase-unauth-check.json"
                redirect_result = self._test_database_write_url(redirect_write_url, json_data)
                results[redirect_write_url] = redirect_result

        return results

    def _test_database_write_url(self, url: str, json_data: dict) -> Dict[str, str]:
        """Test write access to a specific RTDB URL.

        Args:
            url: The database URL to test write access
            json_data: JSON data to write to the database

        Returns:
            Dictionary with write results

        """
        try:
            import json

            # Prepare headers for JSON data
            headers = {"Content-Type": "application/json"}

            # Make POST request to write data
            response = self.session.post(
                url, data=json.dumps(json_data), headers=headers, timeout=self.timeout
            )

            # Handle common status codes with auth retry support
            common_result = self._handle_common_status_codes_with_auth(
                response, url, method="POST", data=json.dumps(json_data), headers=headers
            )
            if common_result:
                # For database write operations, update the message to be more specific
                if response.status_code == 200:
                    common_result["message"] = (
                        "Write access allowed - data written successfully"
                    )
                return common_result

            if response.status_code == 404:
                content = response.text.lower()

                # Check for Firebase error message indicating incorrect URL
                if "firebase error" in content and "configured correctly" in content:
                    return self._build_response_dict(
                        404,
                        "Database not found",
                        False,
                        "PRIVATE",
                        response.text,
                    )

                # Check for region redirect message
                import re
                region_match = re.search(
                    r'https://[^"]+\.firebasedatabase\.app', response.text
                )
                if region_match:
                    region_url = region_match.group(0) + "/.json"
                    return self._build_response_dict(
                        404,
                        "Database lives in different region",
                        False,
                        "REGION_REDIRECT",
                        response.text,
                        region_redirect=region_url,
                    )

                # Check for locked/deactivated database
                if "locked" in content or "deactivated" in content:
                    return self._build_response_dict(
                        423,
                        "Database locked/deactivated",
                        False,
                        "LOCKED",
                        response.text,
                    )

                return self._build_response_dict(
                    404, "Database not found or write protected", False, "NOT_FOUND", response.text
                )

            if response.status_code == 400:
                # Check for specific Firebase RTDB errors
                response_text = response.text.lower()
                if "permission" in response_text or "denied" in response_text:
                    return self._build_response_dict(
                        400,
                        "Write permission denied",
                        False,
                        "WRITE_DENIED",
                        response.text,
                    )
                if "invalid" in response_text:
                    return self._build_response_dict(
                        400,
                        "Invalid data format or path",
                        False,
                        "INVALID_DATA",
                        response.text,
                    )
                return self._build_response_dict(
                    400, "Bad request", False, "BAD_REQUEST", response.text
                )



            if response.status_code == 423:
                return self._build_response_dict(
                    423, "Database locked/deactivated", False, "LOCKED", response.text
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

    def write_to_project_ids(
        self,
        project_ids: Set[str],
        json_file_path: str,
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
    ) -> Dict[str, Dict[str, str]]:
        """Write to Firebase Realtime Databases for multiple project IDs.

        Args:
            project_ids: Set of project IDs to write to
            json_file_path: Path to JSON file containing data to write
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            create_open_only: Whether to create open-only results file (default True)

        Returns:
            Dictionary mapping project IDs to their write results

        """
        return self._scan_projects_base(
            project_ids,
            lambda pid: self.write_to_project_id(pid, json_file_path),
            output_file,
            "Database Write",
            package_project_ids,
            create_open_only,
        )
