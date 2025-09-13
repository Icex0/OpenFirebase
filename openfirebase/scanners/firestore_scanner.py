"""Firestore Scanner for OpenFirebase

Handles Firebase Firestore database scanning functionality.
"""

import time
from typing import Dict, List, Set

import requests

from ..core.config import BLUE, LIME, RESET, YELLOW
from .base import BaseScanner


class FirestoreScanner(BaseScanner):
    """Scans Firebase Firestore databases to check accessibility and security status."""

    def scan_project_id(
        self, project_id: str, collections: List[str] = None
    ) -> Dict[str, str]:
        """Scan a Firebase project ID for Firestore database accessibility.

        Args:
            project_id: The Firebase project ID to scan
            collections: List of collection names to test (defaults to ["users"])

        Returns:
            Dictionary with scan results for different Firestore collection URLs

        """
        if collections is None:
            collections = ["users"]

        results = {}

        for collection_name in collections:
            url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{collection_name}"
            result = self._test_firestore_url(url, collection_name)
            results[url] = result

            # Print result immediately for real-time feedback
            self._print_single_result(url, result)

            # Rate limiting - sleep between requests
            time.sleep(1.0 / self.rate_limit)

        return results

    def _print_single_result(self, url: str, result: Dict[str, str]):
        """Print a single URL result immediately for real-time feedback."""
        status = result.get("status", "unknown")
        security = result.get("security", "unknown")
        message = result.get("message", "No message")

        # Show the full URL and response details
        print(f"URL: {url}")
        print(f"Status: {status}")
        print(f"Response: {message}")

        # Show response content if available
        if "response_content" in result:
            print(f"Content: {result['response_content']}\n")  # Add newline after content for better readability

        # Add status-specific messages
        status_message = self._get_status_message(
            status, security, message, result, "firestore"
        )
        print(f"{status_message}\n")  # Empty line for readability

    def _print_project_header(self, project_id: str, package_names: List[str] = None):
        """Print project header before testing collections."""
        from ..core.config import ORANGE, RESET

        if package_names:
            if len(package_names) == 1:
                print(
                    f"{ORANGE}Project ID: {project_id}{RESET} (from package: {package_names[0]})"
                )
            else:
                print(
                    f"{ORANGE}Project ID: {project_id}{RESET} (from packages: {', '.join(package_names)})"
                )
        else:
            print(f"{ORANGE}Project ID: {project_id}{RESET}")
        print("=" * 80)

    def _test_firestore_url(self, url: str, collection_name: str) -> Dict[str, str]:
        """Test a Firestore URL for accessibility.

        Args:
            url: The Firestore URL to test
            collection_name: The collection name being tested

        Returns:
            Dictionary with scan results

        """
        try:
            response = self.session.get(url, timeout=self.timeout)

            # Handle Firestore-specific responses first for 200 status
            if response.status_code == 200:
                try:
                    response_json = response.json()
                    if response_json == {} or response_json.get("documents") == []:
                        # Public Firestore database but collection doesn't exist
                        return self._build_response_dict(
                            200,
                            f"Firestore database is publicly accessible, but collection '{collection_name}' doesn't exist",
                            True,
                            "PUBLIC_DB_NONEXISTENT_COLLECTION",
                            response.text,
                        )
                    # Collection has content and is accessible
                    return self._build_response_dict(
                        200,
                        f"Firestore collection '{collection_name}' is publicly accessible with data",
                        True,
                        "PUBLIC",
                        response.text,
                    )
                except ValueError:
                    # JSON parsing failed
                    return self._build_response_dict(
                        200,
                        f"Firestore collection '{collection_name}' returned non-JSON response",
                        True,
                        "UNKNOWN",
                        response.text,
                    )

            elif response.status_code == 400:
                # Check for specific Firestore in Datastore Mode error
                if "Firestore in Datastore Mode" in response.text:
                    return self._build_response_dict(
                        400,
                        "Firestore database is in Datastore Mode (empty/unused database)",
                        False,
                        "DATASTORE_MODE",
                        response.text,
                    )
                # Handle other 400 errors generically
                common_result = self._handle_common_status_codes(response)
                if common_result:
                    return common_result

                return self._build_response_dict(
                    response.status_code,
                    f"Unexpected response for Firestore collection '{collection_name}'",
                    False,
                    "UNKNOWN",
                    response.text,
                )
            else:
                # Handle common status codes with authentication retry for non-200 responses
                common_result = self._handle_common_status_codes_with_auth(response, url, "GET")
                if common_result:
                    return common_result

                # Fallback for other status codes
                return self._build_response_dict(
                    response.status_code,
                    f"Unexpected response for Firestore collection '{collection_name}'",
                    False,
                    "UNKNOWN",
                    response.text,
                )

        except requests.exceptions.RequestException as e:
            return self._build_response_dict(
                0,
                f"Request failed for Firestore collection '{collection_name}': {e!s}",
                False,
                "ERROR",
            )

    def scan_project_ids(
        self,
        project_ids: Set[str],
        collections_per_package: Dict[str, Set[str]] = None,
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
        custom_collections: List[str] = None,
    ) -> Dict[str, Dict[str, str]]:
        """Scan Firestore databases for accessibility and security status.

        Args:
            project_ids: Set of project IDs to scan
            collections_per_package: Dictionary mapping package names to sets of collection names
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            create_open_only: Whether to create open-only results file (default True)
            custom_collections: Optional list of collection names to test (overrides defaults)

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
                f.write("Firebase Firestore Read Results\n")
                f.write("=" * 80 + "\n\n")

        for project_id in sorted(project_ids):
            package_names = project_to_packages.get(project_id, [])

            # Print project header immediately before testing
            self._print_project_header(project_id, package_names)

            # Get collection names for this project ID
            if custom_collections:
                # Use custom collections if provided
                collections_to_test = set(custom_collections)
            else:
                # Use default and package-based collections
                collections_to_test = {"users"}  # Default collection

                if collections_per_package and package_project_ids:
                    for package_name, project_id_set in package_project_ids.items():
                        if (
                            project_id in project_id_set
                            and package_name in collections_per_package
                        ):
                            collections_to_test.update(
                                collections_per_package[package_name]
                            )

            project_results = self.scan_project_id(
                project_id, list(collections_to_test)
            )
            results[project_id] = project_results

            # Display authenticated results during individual scanning (verbose format)
            self._display_verbose_authenticated_results(project_results)

            # Note: Don't overwrite original results with authenticated results
            # The base scanner's _display_and_clear_authenticated_results will handle showing both
            # Just track if we found publicly accessible databases for fuzzing decision
            has_public_access = False
            for url, auth_result in list(self.authenticated_results.items()):
                if auth_result.get("security") == "PUBLIC_AUTH" and auth_result.get("status") == "200":
                    # ANY authenticated access means the database is accessible - trigger fuzzing
                    has_public_access = True
                    break

            # Check if we should perform fuzzing for this project
            should_fuzz = False
            if self.fuzz_collections and self.wordlist:
                # Check main results for publicly accessible databases
                for result in project_results.values():
                    # Fuzz if we find any publicly accessible Firestore database
                    if result.get("security") in ["PUBLIC", "PUBLIC_DB_NONEXISTENT_COLLECTION"]:
                        should_fuzz = True
                        break

                # Also check if we have authenticated access
                if has_public_access:
                    should_fuzz = True

            # Store authenticated results for this project before any potential clearing
            if self.authenticated_results:
                self.all_authenticated_results[project_id] = self.authenticated_results.copy()

            # Clear authenticated results to avoid carryover to next project
            self.authenticated_results.clear()

            # Perform collection fuzzing if enabled and we found a public database
            if should_fuzz:
                print(
                    f"{BLUE}[INF]{RESET} Firestore database is publicly accessible! Fuzzing {len(self.wordlist)} collection names..."
                )

                found_collections = []

                for i, collection_name in enumerate(self.wordlist, 1):
                    # Skip collections we already tested
                    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{collection_name}"
                    if url in project_results:
                        continue

                    if i % 20 == 0:  # Progress indicator every 20 requests
                        print(
                            f"   Fuzzing progress: {i}/{len(self.wordlist)} collections tested..."
                        )

                    # Make request (authenticated if available, otherwise unauthenticated)
                    if self.firebase_auth:
                        auth_token = self.firebase_auth.get_auth_token(project_id)
                        if auth_token:
                            try:
                                # Use Authorization header for Firestore
                                auth_headers = {"Authorization": f"Bearer {auth_token}"}
                                auth_response = self.session.get(url, headers=auth_headers, timeout=self.timeout)

                                if auth_response.status_code == 200:
                                    # Check if collection has data or is empty
                                    try:
                                        import json
                                        response_json = auth_response.json()
                                        if response_json == {} or response_json.get("documents") == []:
                                            # Empty collection - don't add to results or auth tracking to avoid verbose output
                                            pass
                                        else:
                                            # Collection has data - add to results, auth tracking, and announce
                                            result = self._build_response_dict(
                                                200,
                                                f"Firestore collection '{collection_name}' is publicly accessible with authentication",
                                                True,
                                                "PUBLIC_AUTH",
                                                auth_response.text,
                                            )
                                            project_results[url] = result
                                            found_collections.append(collection_name)
                                            # Only add to auth success tracking if collection has actual data
                                            self.auth_success_urls.add(url)
                                            print(f"   {LIME}[+]{RESET} Found public collection with data (authenticated): {collection_name}")
                                    except (ValueError, json.JSONDecodeError):
                                        # Can't parse JSON, treat as having data
                                        result = self._build_response_dict(
                                            200,
                                            f"Firestore collection '{collection_name}' is publicly accessible with authentication",
                                            True,
                                            "PUBLIC_AUTH",
                                            auth_response.text,
                                        )
                                        project_results[url] = result
                                        found_collections.append(collection_name)
                                        # Only add to auth success tracking if collection has actual data
                                        self.auth_success_urls.add(url)
                                        print(f"   {LIME}[+]{RESET} Found public collection with data (authenticated): {collection_name}")
                                # Don't add failed/protected collections to results to avoid verbose output
                            except Exception:
                                # Ignore request failures during fuzzing
                                pass
                    else:
                        # Unauthenticated fuzzing - make regular HTTP requests
                        try:
                            response = self.session.get(url, timeout=self.timeout)

                            if response.status_code == 200:
                                # Check if collection has data or is empty
                                try:
                                    import json
                                    response_json = response.json()
                                    if response_json == {} or response_json.get("documents") == []:
                                        # Empty collection - don't add to results to avoid verbose output
                                        pass
                                    else:
                                        # Collection has data - add to results and announce
                                        result = self._build_response_dict(
                                            200,
                                            f"Firestore collection '{collection_name}' is publicly accessible with data",
                                            True,
                                            "PUBLIC",
                                            response.text,
                                        )
                                        project_results[url] = result
                                        found_collections.append(collection_name)
                                        print(f"   {LIME}[+]{RESET} Found public collection with data: {collection_name}")
                                except (ValueError, json.JSONDecodeError):
                                    # Can't parse JSON, treat as having data
                                    result = self._build_response_dict(
                                        200,
                                        f"Firestore collection '{collection_name}' is publicly accessible",
                                        True,
                                        "PUBLIC",
                                        response.text,
                                    )
                                    project_results[url] = result
                                    found_collections.append(collection_name)
                                    print(f"   {LIME}[+]{RESET} Found public collection with data: {collection_name}")
                            # Don't add failed/protected collections to results to avoid verbose output
                        except Exception:
                            # Ignore request failures during fuzzing
                            pass

                    # Rate limiting - sleep between requests
                    time.sleep(1.0 / self.rate_limit)

                # Print fuzzing summary
                print(f"{BLUE}[INF]{RESET} Fuzzing completed for project {project_id}:")
                if found_collections:
                    print(f"   {LIME}[+]{RESET} Found {len(found_collections)} public collection(s) with data")
                    for collection in found_collections:
                        print(f"      - {collection}")
                else:
                    print(f"   {YELLOW}[!]{RESET} No public collections with data found\\n")

            # Note: authenticated results already stored above before fuzzing

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

        # Save final summary
        if output_file:
            self._save_final_summary_to_file(results, output_file, "firestore", is_write_operation=False)

            # Create open-only results file if requested (for single scans)
            if create_open_only:
                self._save_open_only_results(
                    results, output_file, "firestore", package_project_ids
                )

        return results

    def scan_firestore(
        self,
        project_ids: Set[str],
        collections_per_package: Dict[str, Set[str]] = None,
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
        custom_collections: List[str] = None,
    ) -> Dict[str, Dict[str, str]]:
        """Scan Firestore databases (alias for scan_project_ids for backward compatibility).

        Args:
            project_ids: Set of project IDs to scan
            collections_per_package: Dictionary mapping package names to sets of collection names
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            create_open_only: Whether to create open-only results file (default True)
            custom_collections: Optional list of collection names to test (overrides defaults)

        Returns:
            Dictionary mapping project IDs to their scan results

        """
        return self.scan_project_ids(
            project_ids,
            collections_per_package,
            package_project_ids,
            output_file,
            create_open_only,
            custom_collections,
        )

    def write_to_project_id(self, project_id: str, write_value: str) -> Dict[str, str]:
        """Write a document to Firestore database for a specific project ID.

        Args:
            project_id: The Firebase project ID to write to
            write_value: The string value to write to Firestore

        Returns:
            Dictionary with write results for the Firestore database URL

        """
        results = {}

        # Firestore write URL - writing to a test collection/document
        url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/firestore_unauthenticated_access"
        result = self._test_firestore_write_url(url, write_value)
        results[url] = result

        return results

    def _test_firestore_write_url(self, url: str, write_value: str) -> Dict[str, str]:
        """Test write access to a specific Firestore URL.

        Args:
            url: The Firestore URL to test write access
            write_value: The string value to write

        Returns:
            Dictionary with write results

        """
        try:
            # Prepare Firestore document payload
            payload = {
                "fields": {
                    "title": {
                        "stringValue": write_value
                    }
                }
            }

            # Prepare headers for JSON request
            headers = {"Content-Type": "application/json"}

            # Make POST request to write document
            response = self.session.post(
                url, json=payload, headers=headers, timeout=self.timeout
            )

            # Handle common status codes with auth retry support
            common_result = self._handle_common_status_codes_with_auth(
                response, url, method="POST", json=payload, headers=headers
            )
            if common_result:
                # For Firestore write operations, update the message to be more specific
                if response.status_code == 200:
                    common_result["message"] = (
                        "Document write successful - write access allowed"
                    )
                return common_result

            if response.status_code == 400:
                # Check for specific Firestore errors
                response_text = response.text.lower()
                if "firestore in datastore mode" in response_text:
                    return self._build_response_dict(
                        400,
                        "Firestore database is in Datastore Mode (empty/unused database)",
                        False,
                        "DATASTORE_MODE",
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
                    404, "Firestore database not found", False, "NOT_FOUND", response.text
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
        except Exception as e:
            return self._build_response_dict(0, f"Error: {e!s}", False, "ERROR")

    def write_to_project_ids(
        self,
        project_ids: Set[str],
        write_value: str,
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
    ) -> Dict[str, Dict[str, str]]:
        """Write to Firestore databases for multiple project IDs.

        Args:
            project_ids: Set of project IDs to write to
            write_value: The string value to write to Firestore
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Optional output file to save results gradually
            create_open_only: Whether to create open-only results file (default True)

        Returns:
            Dictionary mapping project IDs to their write results

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
                f.write("Firebase Firestore Write Results\n")
                f.write("=" * 80 + "\n\n")

        for project_id in sorted(project_ids):
            # Check for shutdown request
            from ..utils import is_shutdown_requested
            if is_shutdown_requested():
                from ..core.config import RED, RESET
                print(f"\n{RED}[X]{RESET} Shutdown requested. Stopping Firestore write...")
                break

            package_names = project_to_packages.get(project_id, [])

            # Print project header
            self._print_project_header(project_id, package_names)

            # Perform write test
            project_results = self.write_to_project_id(project_id, write_value)
            results[project_id] = project_results

            # Print results to console
            for url, result in project_results.items():
                self._print_single_result(url, result)

            # Display authenticated results during individual scanning (verbose format)
            self._display_verbose_authenticated_results(project_results)

            # Store authenticated results for this project before any potential clearing
            if self.authenticated_results:
                self.all_authenticated_results[project_id] = self.authenticated_results.copy()

            # Clear authenticated results to avoid carryover to next project
            self.authenticated_results.clear()

            # Save results gradually if output file is provided
            if output_file:
                self._save_project_results_to_file(
                    project_id, project_results, output_file, package_names
                )
                # Save authenticated results to file (if any exist)
                if project_id in self.all_authenticated_results:
                    self._save_authenticated_results_to_file_for_project(
                        project_id, output_file
                    )

            # Rate limiting - sleep between requests
            time.sleep(1.0 / self.rate_limit)

        # Save final summary
        if output_file:
            self._save_final_summary_to_file(results, output_file, "firestore", is_write_operation=True)

            # Create open-only results file if requested (for single scans)
            if create_open_only:
                self._save_open_only_results(
                    results, output_file, "firestore", package_project_ids
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
                    status, security, message, result, "firestore"
                )
                f.write(f"{status_message}\n")
                f.write("\n")

            f.write("\n")

    def _save_final_summary_to_file(
        self, results: Dict[str, Dict[str, str]], output_file: str, resource_type: str, is_write_operation: bool = False
    ):
        """Save final summary to file."""
        with open(output_file, "a", encoding="utf-8") as f:
            counts = self._count_scan_results(results, resource_type)
            labels = self._get_summary_labels(resource_type)

            operation_type = "WRITE" if is_write_operation else "READ"
            f.write(f"[UNAUTH] SCAN SUMMARY FIREBASE FIRESTORE {operation_type}\n")
            f.write("=" * 80 + "\n")
            f.write(f"Total projects scanned: {counts['total_projects']}\n")

            # Use different labels for write vs read operations
            if is_write_operation:
                f.write(f"Projects with Firestore write access allowed: {counts['public_count']}\n")
                f.write(f"Projects with write access denied (401/403): {counts['protected_count']}\n")
            else:
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
            elif resource_type == "firestore":
                if is_write_operation:
                    f.write(
                        f"Projects in Datastore Mode (empty/unused): {counts['datastore_mode_count']}\n"
                    )
                    f.write(
                        f"Projects with successful write operations: {counts['public_count']}\n"
                    )
                else:
                    f.write(
                        f"{labels['datastore_mode']}: {counts['datastore_mode_count']}\n"
                    )
                    if counts["total_open_collections_count"] > 0:
                        f.write(
                            f"{labels['total_open_collections']}: {counts['total_open_collections_count']}\n"
                        )

            if counts["rate_limited_count"] > 0:
                f.write(f"{labels['rate_limited']}: {counts['rate_limited_count']}\n")
            f.write(f"{labels['other']}: {counts['other_count']}\n")

            if counts["public_count"] > 0:
                if resource_type == "storage":
                    resource_word = "storage buckets"
                    access_desc = "are accessible without authentication"
                elif resource_type == "config":
                    resource_word = "remote configs"
                    access_desc = "are accessible without authentication"
                elif resource_type == "firestore":
                    if is_write_operation:
                        resource_word = "Firestore databases with write access"
                        access_desc = "allow unauthenticated writing"
                    else:
                        resource_word = "Firestore databases"
                        access_desc = "are accessible without authentication"
                else:
                    resource_word = "databases"
                    access_desc = "are accessible without authentication"

                warning_word = "public" if not (resource_type == "firestore" and is_write_operation) else ""
                f.write(
                    f"\nWARNING: {counts['public_count']} {warning_word} {resource_word} found!\n".replace("  ", " ")
                )
                f.write(
                    f"These {resource_word.split(' with')[0] if 'with' in resource_word else resource_word} {access_desc}.\n"
                )
