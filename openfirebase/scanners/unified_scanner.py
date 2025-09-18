"""Firebase Scanner Module

Unified Firebase scanner that combines all scanning functionality.
"""

from typing import Dict, Set

from .config_scanner import ConfigScanner
from .database_scanner import DatabaseScanner
from .firestore_scanner import FirestoreScanner
from .storage_scanner import StorageScanner


class FirebaseScanner:
    """Unified Firebase scanner that combines all scanning functionality.

    This class provides backward compatibility with the original FirebaseScanner
    while utilizing the new modular scanner architecture.
    """

    def __init__(
        self,
        timeout: int = 10,
        rate_limit: float = 1.0,
        fuzz_collections_wordlist: str = None,
        proxy: str = None,
        firebase_auth=None,
    ):
        """Initialize the unified scanner with all sub-scanners.

        Args:
            timeout: Request timeout in seconds
            rate_limit: Requests per second (default: 1.0)
            fuzz_collections_wordlist: Path to wordlist file for collection fuzzing (enables fuzzing if provided)
            proxy: Proxy URL for HTTP requests (format: protocol://host:port)
            firebase_auth: FirebaseAuth instance for authenticated requests

        """
        # Store configuration for direct access
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.fuzz_collections = bool(fuzz_collections_wordlist)
        self.wordlist_path = fuzz_collections_wordlist
        self.firebase_auth = firebase_auth

        # Load wordlist once at the unified scanner level to avoid duplicate logging
        self.wordlist = []
        if self.fuzz_collections:
            self._load_wordlist()

        # Initialize all sub-scanners with the same configuration
        # Pass None for fuzz_collections_wordlist to prevent duplicate wordlist loading
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
            timeout, rate_limit, None, proxy
        )

        # Share the loaded wordlist with all sub-scanners
        if self.fuzz_collections:
            self.database_scanner.wordlist = self.wordlist
            self.database_scanner.fuzz_collections = True
            self.storage_scanner.wordlist = self.wordlist
            self.storage_scanner.fuzz_collections = True
            self.firestore_scanner.wordlist = self.wordlist
            self.firestore_scanner.fuzz_collections = True
            self.config_scanner.wordlist = self.wordlist
            self.config_scanner.fuzz_collections = True

    def _load_wordlist(self):
        """Load collection names from wordlist file."""
        from ..utils import load_wordlist

        self.wordlist, success = load_wordlist(self.wordlist_path)
        if not success:
            self.fuzz_collections = False

    # Database scanning methods
    def scan_project_id(self, project_id: str):
        """Scan a Firebase project ID to check database accessibility."""
        return self.database_scanner.scan_project_id(project_id)

    def scan_project_ids(
        self,
        project_ids,
        package_project_ids=None,
        output_file=None,
        create_open_only=True,
    ):
        """Scan multiple project IDs with rate limiting and gradual file saving."""
        return self.database_scanner.scan_project_ids(
            project_ids, package_project_ids, output_file, create_open_only
        )

    def scan_databases(
        self,
        project_ids,
        package_project_ids=None,
        output_file=None,
        create_open_only=True,
    ):
        """Scan Firebase databases (alias for scan_project_ids for backward compatibility)."""
        return self.database_scanner.scan_databases(
            project_ids, package_project_ids, output_file, create_open_only
        )

    # Storage scanning methods
    def scan_storage_buckets(
        self,
        project_ids,
        package_project_ids=None,
        output_file=None,
        create_open_only=True,
    ):
        """Scan Firebase storage buckets for accessibility and security status."""
        return self.storage_scanner.scan_storage_buckets(
            project_ids, package_project_ids, output_file, create_open_only
        )

    # Storage write methods
    def write_to_storage_buckets(
        self,
        project_ids,
        file_path: str,
        package_project_ids=None,
        output_file=None,
        create_open_only=True,
    ):
        """Write to Firebase storage buckets for multiple project IDs."""
        return self.storage_scanner.write_to_project_ids(
            project_ids, file_path, package_project_ids, output_file, create_open_only
        )

    # Database (RTDB) write methods
    def write_to_databases(
        self,
        project_ids,
        json_file_path: str,
        package_project_ids=None,
        output_file=None,
        create_open_only=True,
    ):
        """Write to Firebase Realtime Databases for multiple project IDs."""
        return self.database_scanner.write_to_project_ids(
            project_ids, json_file_path, package_project_ids, output_file, create_open_only
        )

    # Firestore scanning methods
    def scan_firestore(
        self,
        project_ids,
        collections_per_package=None,
        package_project_ids=None,
        output_file=None,
        create_open_only=True,
        custom_collections=None,
    ):
        """Scan Firestore databases for accessibility and security status."""
        return self.firestore_scanner.scan_firestore(
            project_ids,
            collections_per_package,
            package_project_ids,
            output_file,
            create_open_only,
            custom_collections,
        )

    # Firestore write methods
    def write_to_firestore_databases(
        self,
        project_ids,
        write_value: str,
        package_project_ids=None,
        output_file=None,
        create_open_only=True,
    ):
        """Write to Firestore databases for multiple project IDs."""
        return self.firestore_scanner.write_to_project_ids(
            project_ids, write_value, package_project_ids, output_file, create_open_only
        )

    # Config scanning methods
    def scan_config(self, config_data, package_project_ids=None, output_file=None):
        """Scan Firebase Remote Config for accessibility and security status."""
        return self.config_scanner.scan_config(
            config_data, package_project_ids, output_file
        )

    # Delegate methods - These methods delegate to the base scanner implementation
    def print_scan_results(
        self, scan_results, scan_type="DATABASES", package_project_ids=None
    ):
        """Print scan results to console with color coding."""
        # Delegate to the correct scanner based on scan type
        if scan_type in ["STORAGE", "STORAGE WRITE"]:
            return self.storage_scanner.print_scan_results(
                scan_results, scan_type, package_project_ids
            )
        if scan_type in ["FIRESTORE", "FIRESTORE WRITE"]:
            return self.firestore_scanner.print_scan_results(
                scan_results, scan_type, package_project_ids
            )
        if scan_type in ["CONFIG", "REMOTE CONFIG"]:
            return self.config_scanner.print_scan_results(
                scan_results, scan_type, package_project_ids
            )
        # Default to database scanner for database scans and unknown types
        return self.database_scanner.print_scan_results(
            scan_results, scan_type, package_project_ids
        )

    def print_scan_details(
        self, scan_results, scan_type="DATABASES", package_project_ids=None
    ):
        """Print only the detailed scan results to console (without summary)."""
        # Delegate to the correct scanner based on scan type
        if scan_type in ["STORAGE", "STORAGE WRITE"]:
            return self.storage_scanner.print_scan_details(
                scan_results, scan_type, package_project_ids
            )
        if scan_type in ["FIRESTORE", "FIRESTORE WRITE"]:
            return self.firestore_scanner.print_scan_details(
                scan_results, scan_type, package_project_ids
            )
        if scan_type in ["CONFIG", "REMOTE CONFIG"]:
            return self.config_scanner.print_scan_details(
                scan_results, scan_type, package_project_ids
            )
        # Default to database scanner for database scans and unknown types
        return self.database_scanner.print_scan_details(
            scan_results, scan_type, package_project_ids
        )

    def print_scan_summary(self, scan_results, scan_type="DATABASES", output_dir=None):
        """Print only the scan summary (counts and totals) to console."""
        # Delegate to the correct scanner based on scan type
        if scan_type in ["STORAGE", "STORAGE WRITE"]:
            return self.storage_scanner.print_scan_summary(scan_results, scan_type, output_dir)
        if scan_type in ["FIRESTORE", "FIRESTORE WRITE"]:
            return self.firestore_scanner.print_scan_summary(scan_results, scan_type, output_dir)
        if scan_type in ["CONFIG", "REMOTE CONFIG"]:
            return self.config_scanner.print_scan_summary(scan_results, scan_type, output_dir)
        # Default to database scanner for database scans and unknown types
        return self.database_scanner.print_scan_summary(scan_results, scan_type, output_dir)

    def save_combined_scan_results(
        self,
        db_scan_results=None,
        storage_scan_results=None,
        config_scan_results=None,
        firestore_scan_results=None,
        storage_write_results=None,
        rtdb_write_results=None,
        firestore_write_results=None,
        output_file=None,
        package_project_ids=None,
        print_warnings=True,
    ):
        """Save combined scan results from multiple scanners."""
        return self.database_scanner.save_combined_scan_results(
            db_scan_results,
            storage_scan_results,
            config_scan_results,
            firestore_scan_results,
            storage_write_results,
            rtdb_write_results,
            firestore_write_results,
            output_file,
            package_project_ids,
            print_warnings,
        )

    def get_read_auth_success_summary(self) -> Dict[str, Set[str]]:
        """Get summary of read authentication successes from all scanners.
        
        Returns:
            Dictionary mapping scanner types to sets of URLs that required authentication for read operations

        """
        return {
            "database": self.database_scanner.get_read_auth_success_urls(),
            "storage": self.storage_scanner.get_read_auth_success_urls(),
            "firestore": self.firestore_scanner.get_read_auth_success_urls(),
        }
    
    def get_write_auth_success_summary(self) -> Dict[str, Set[str]]:
        """Get summary of write authentication successes from all scanners.
        
        Returns:
            Dictionary mapping scanner types to sets of URLs that required authentication for write operations

        """
        return {
            "database": self.database_scanner.get_write_auth_success_urls(),
            "storage": self.storage_scanner.get_write_auth_success_urls(),
            "firestore": self.firestore_scanner.get_write_auth_success_urls(),
        }

    def get_authenticated_results(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        """Get all authenticated results from all scanners.
        
        Returns:
            Dictionary mapping project_id -> url -> auth_result_data

        """
        all_results = {}
        # Merge results from all scanners
        for scanner in [self.database_scanner, self.storage_scanner, self.firestore_scanner, self.config_scanner]:
            for project_id, project_results in scanner.all_authenticated_results.items():
                if project_id not in all_results:
                    all_results[project_id] = {}
                all_results[project_id].update(project_results)
        return all_results

    def clear_all_authenticated_results(self):
        """Clear all authenticated results from all scanners."""
        self.database_scanner.clear_all_authenticated_results()
        self.storage_scanner.clear_all_authenticated_results()
        self.firestore_scanner.clear_all_authenticated_results()
        self.config_scanner.clear_all_authenticated_results()
