"""Firebase Scanner Module

Provides a registry of all Firebase scanners with shared configuration.
Individual scanners handle their own display logic via polymorphism.
"""

from typing import Dict, Set

from .cloud_functions_scanner import CloudFunctionsScanner
from .config_scanner import ConfigScanner
from .database_scanner import DatabaseScanner
from .firestore_scanner import FirestoreScanner
from .storage_scanner import StorageScanner


class FirebaseScanner:
    """Registry of Firebase scanners with shared configuration.

    Creates and holds all scanner instances, provides aggregation methods
    for auth results, and delegates combined file output.
    """

    def __init__(
        self,
        timeout: int = 10,
        rate_limit: float = 1.0,
        fuzz_collections_wordlist: str = None,
        proxy: str = None,
        firebase_auth=None,
        referer: str = None,
        ios_bundle_id: str = None,
    ):
        """Initialize all scanners with shared configuration."""
        # Store configuration
        self.fuzz_collections = bool(fuzz_collections_wordlist)
        self.wordlist_path = fuzz_collections_wordlist

        # Load wordlist once to avoid duplicate logging
        self.wordlist = []
        if self.fuzz_collections:
            self._load_wordlist()

        # Initialize all scanners — pass None for wordlist to prevent duplicate loading
        self.database_scanner = DatabaseScanner(
            timeout, rate_limit, None, proxy, firebase_auth
        )
        self.storage_scanner = StorageScanner(
            timeout, rate_limit, None, proxy, firebase_auth
        )
        self.firestore_scanner = FirestoreScanner(
            timeout, rate_limit, None, proxy, firebase_auth
        )
        self.config_scanner = ConfigScanner(
            timeout, rate_limit, None, proxy,
            referer=referer, ios_bundle_id=ios_bundle_id,
        )
        self.cloud_functions_scanner = CloudFunctionsScanner(
            timeout, rate_limit, None, proxy, firebase_auth
        )

        # Share loaded wordlist with sub-scanners
        if self.fuzz_collections:
            for scanner in [self.database_scanner, self.storage_scanner,
                            self.firestore_scanner, self.config_scanner]:
                scanner.wordlist = self.wordlist
                scanner.fuzz_collections = True

    def _load_wordlist(self):
        """Load collection names from wordlist file."""
        from ..utils import load_wordlist
        self.wordlist, success = load_wordlist(self.wordlist_path)
        if not success:
            self.fuzz_collections = False

    @property
    def _all_scanners(self):
        return [
            self.database_scanner, self.storage_scanner,
            self.firestore_scanner, self.config_scanner,
            self.cloud_functions_scanner,
        ]

    # --- Aggregation methods ---

    def get_read_auth_success_summary(self) -> Dict[str, Set[str]]:
        """Get summary of read authentication successes from all scanners."""
        return {
            "database": self.database_scanner.get_read_auth_success_urls(),
            "storage": self.storage_scanner.get_read_auth_success_urls(),
            "firestore": self.firestore_scanner.get_read_auth_success_urls(),
            "cloud_functions": self.cloud_functions_scanner.get_read_auth_success_urls(),
        }

    def get_write_auth_success_summary(self) -> Dict[str, Set[str]]:
        """Get summary of write authentication successes from all scanners."""
        return {
            "database": self.database_scanner.get_write_auth_success_urls(),
            "storage": self.storage_scanner.get_write_auth_success_urls(),
            "firestore": self.firestore_scanner.get_write_auth_success_urls(),
            "cloud_functions": self.cloud_functions_scanner.get_write_auth_success_urls(),
        }

    def get_authenticated_results(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        """Get all authenticated results from all scanners."""
        all_results = {}
        for scanner in self._all_scanners:
            for project_id, project_results in scanner.all_authenticated_results.items():
                if project_id not in all_results:
                    all_results[project_id] = {}
                all_results[project_id].update(project_results)
        return all_results

    def clear_all_authenticated_results(self):
        """Clear all authenticated results from all scanners."""
        for scanner in self._all_scanners:
            scanner.clear_all_authenticated_results()

    def save_combined_scan_results(
        self,
        scan_sections,
        output_file=None,
        package_project_ids=None,
        all_auth_results=None,
    ):
        """Save combined scan results using the first available scanner.

        Args:
            scan_sections: List of (scanner, results, title) tuples
            output_file: Path to save results
            package_project_ids: Dictionary mapping package names to sets of project IDs
            all_auth_results: Authenticated results by project_id

        """
        if not scan_sections:
            return []
        # Use the first scanner's save_combined_scan_results (the method is on BaseScanner)
        return scan_sections[0][0].save_combined_scan_results(
            scan_sections, output_file, package_project_ids, all_auth_results,
        )
