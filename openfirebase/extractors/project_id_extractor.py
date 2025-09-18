"""Project ID Extractor Module

This module extracts unique Firebase project IDs from various Firebase URL patterns.
"""

import re
from typing import Dict, List, Set, Tuple

from ..core.config import ORANGE, RESET
from ..parsers.pattern_loader import get_firebase_patterns, get_pattern_metadata


class ProjectIDExtractor:
    """Extracts unique Firebase project IDs from Firebase URLs."""

    @staticmethod
    def extract_project_ids_from_urls(
        firebase_items: List[Tuple[str, str]],
    ) -> Set[str]:
        """Extract unique project IDs from a list of Firebase items.

        Args:
            firebase_items: List of tuples containing (header, url) pairs

        Returns:
            Set of unique project IDs

        """
        from ..core.config import INVALID_PROJECT_IDS

        project_ids = set()

        for header, url in firebase_items:
            # If it's already a Firebase_Project_ID or Other_Firebase_Project_ID, use it directly
            if header in ["Firebase_Project_ID", "Other_Firebase_Project_ID"]:
                if url not in INVALID_PROJECT_IDS:
                    # Remove "-default-rtdb" suffix if present
                    clean_project_id = url.replace("-default-rtdb", "")
                    project_ids.add(clean_project_id)
                continue

            # Extract project ID from URL using main Firebase patterns with capture groups
            all_patterns = get_firebase_patterns()
            pattern_metadata = get_pattern_metadata()

            for pattern_name, pattern in all_patterns.items():
                # Skip patterns that don't contain URLs (like Firebase_Project_ID, Firestore collections)
                if pattern_name in [
                    "Firebase_Project_ID",
                    "Other_Firebase_Project_ID",
                    "Google_API_Key",
                    "Other_Google_API_Key",
                    "Google_App_ID",
                    "Other_Google_App_ID",
                    "Firestore_Collection_Name",
                ]:
                    continue

                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    # Extract project ID from capture group 1 (since all URL patterns now have project ID in group 1)
                    if match.groups() and len(match.groups()) > 0:
                        project_id = match.group(1)
                        # Validate project ID format and filter out invalid ones
                        if (
                            re.match(r"^[a-z0-9-]+$", project_id)
                            and project_id not in INVALID_PROJECT_IDS
                        ):
                            # Remove "-default-rtdb" suffix if present
                            clean_project_id = project_id.replace("-default-rtdb", "")
                            project_ids.add(clean_project_id)
                        break

        return project_ids

    @staticmethod
    def extract_project_ids_from_results(
        results: Dict[str, List[Tuple[str, str]]],
    ) -> Dict[str, Set[str]]:
        """Extract unique project IDs for each package from Firebase results.

        Args:
            results: Dictionary mapping package names to lists of Firebase items

        Returns:
            Dictionary mapping package names to sets of unique project IDs

        """
        package_project_ids = {}

        for package_name, firebase_items in results.items():
            project_ids = ProjectIDExtractor.extract_project_ids_from_urls(
                firebase_items
            )
            if project_ids:
                package_project_ids[package_name] = project_ids

        return package_project_ids

    @staticmethod
    def save_project_ids(
        package_project_ids: Dict[str, Set[str]],
        output_file: str = "firebase_project_ids.txt",
    ):
        """Save project IDs to a file.

        Args:
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Output file name

        """
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("Firebase Project IDs by Package\n")
            f.write("=" * 50 + "\n\n")

            for package_name, project_ids in sorted(package_project_ids.items()):
                f.write(f"Package: {package_name}\n")
                f.write("-" * 30 + "\n")
                for project_id in sorted(project_ids):
                    f.write(f"  {project_id}\n")
                f.write(f"\nTotal: {len(project_ids)} project ID(s)\n\n")

            # Summary
            total_packages = len(package_project_ids)
            total_project_ids = sum(len(ids) for ids in package_project_ids.values())
            unique_project_ids = set()
            for ids in package_project_ids.values():
                unique_project_ids.update(ids)

            f.write("SUMMARY\n")
            f.write("=" * 50 + "\n")
            f.write(f"Total packages: {total_packages}\n")
            f.write(f"Total project ID instances: {total_project_ids}\n")
            f.write(f"Unique project IDs: {len(unique_project_ids)}\n")
            f.write("\nAll unique project IDs:\n")
            for project_id in sorted(unique_project_ids):
                f.write(f"  {project_id}\n")

    @staticmethod
    def save_clean_project_ids(
        package_project_ids: Dict[str, Set[str]],
        output_file: str = "firebase_project_ids_clean.txt",
    ):
        """Save only the clean list of unique project IDs to a file (one per line).

        Args:
            package_project_ids: Dictionary mapping package names to sets of project IDs
            output_file: Output file name

        """
        # Get all unique project IDs
        unique_project_ids = set()
        for ids in package_project_ids.values():
            unique_project_ids.update(ids)

        with open(output_file, "w", encoding="utf-8") as f:
            for project_id in sorted(unique_project_ids):
                f.write(f"{project_id}\n")

    @staticmethod
    def print_project_ids(
        package_project_ids: Dict[str, Set[str]],
        firebase_results: Dict[str, List[Tuple[str, str]]] = None,
    ):
        """Print project IDs to console.

        Args:
            package_project_ids: Dictionary mapping package names to sets of project IDs
            firebase_results: Dictionary mapping package names to lists of Firebase items (optional)

        """
        print("\n" + "=" * 60)
        print(f"{ORANGE}FIREBASE PROJECT IDS{RESET}")
        print("=" * 60)

        for package_name, project_ids in sorted(package_project_ids.items()):
            print(f"\n{ORANGE}Package: {package_name}{RESET}")
            print("-" * 40)
            for project_id in sorted(project_ids):
                print(f"  {project_id}")
            print(f"\nTotal: {len(project_ids)} project ID(s)")

        # Summary
        total_packages = len(package_project_ids)
        total_project_ids = sum(len(ids) for ids in package_project_ids.values())
        unique_project_ids = set()
        for ids in package_project_ids.values():
            unique_project_ids.update(ids)

        # Calculate total Firebase items if results are provided
        total_firebase_items = 0
        if firebase_results:
            total_firebase_items = sum(
                len(items) for items in firebase_results.values()
            )

        print("\n" + "=" * 60)
        print(f"{ORANGE}EXTRACTION SUMMARY{RESET}")
        print("=" * 60)
        print(f"Total packages processed: {total_packages}")
        if firebase_results:
            print(f"Total unique Firebase items found: {total_firebase_items}")
        print(f"Total project ID instances: {total_project_ids}")
        print(f"Unique project IDs: {len(unique_project_ids)}")
        print("\nAll unique project IDs:")
        for project_id in sorted(unique_project_ids):
            print(f"  {project_id}")
        print("=" * 60)
