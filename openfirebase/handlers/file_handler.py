"""File Handler Module

This module handles all file I/O operations for the OpenFirebase tool.
"""

import re
from typing import Dict, List, Set, Tuple

from ..core.config import FILTERED_COLLECTION_VALUES, GREEN, RESET
from ..parsers.pattern_loader import get_invalid_collection_prefixes


class FileHandler:
    """Handles file I/O operations for Firebase link results."""

    @staticmethod
    def _is_valid_collection_name(collection_name: str) -> bool:
        """Check if a collection name is valid (not a false positive).

        Args:
            collection_name: The collection name to validate

        Returns:
            True if the collection name is valid, False if it should be filtered out

        """
        # Get invalid prefixes from centralized configuration
        invalid_prefixes = get_invalid_collection_prefixes()

        # Check if the collection name starts with any invalid prefix
        for prefix in invalid_prefixes:
            if collection_name.startswith(prefix):
                return False

        # Check if the collection name is in the filtered values list
        if collection_name.lower() in [value.lower() for value in FILTERED_COLLECTION_VALUES]:
            return False

        return True

    @staticmethod
    def save_single_result(
        package_name: str,
        links: List[Tuple[str, str]],
        output_file: str = "firebase_items.txt",
    ):
        """Save a single package result to the output file (append mode)."""
        try:
            # Ensure the output directory exists
            from pathlib import Path

            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, "a", encoding="utf-8") as file:
                file.write(f"=== {package_name} ===\n")

                # Group links by header type (strip source labels for grouping)
                grouped_links = {}
                for header, value in links:
                    # Extract base header by removing source labels like "(JADX)" or "(Fast)"
                    base_header = re.sub(r"\s*\([^)]+\)$", "", header)

                    # Filter out invalid collection names for collection headers
                    if "Collection" in base_header:
                        if not FileHandler._is_valid_collection_name(value):
                            continue

                    if base_header not in grouped_links:
                        grouped_links[base_header] = []
                    grouped_links[base_header].append((header, value))

                # Write grouped results
                for base_header, items in grouped_links.items():
                    file.write(f"[{base_header}]\n")
                    for header, value in items:
                        # Show source info if it exists
                        source_info = re.search(r"\s*(\([^)]+\))$", header)
                        if source_info:
                            file.write(f"- {value} {source_info.group(1)}\n")
                        else:
                            file.write(f"- {value}\n")
                file.write("\n")
        except Exception as e:
            # Return error for main process to handle with tqdm.write()
            raise Exception(f"Error saving results for {package_name}: {e}")

    @staticmethod
    def clear_output_file(output_file: str = "firebase_items.txt"):
        """Clear the output file at the start of processing."""
        try:
            with open(output_file, "w", encoding="utf-8") as file:
                file.write("")  # Create/clear the file
        except Exception as e:
            print(f"Error clearing output file: {e}")

    @staticmethod
    def print_results(results: Dict[str, List[Tuple[str, str]]]):
        """Print extracted results to console using bullet-point format (same as directory mode)."""
        if not results:
            print("No Firebase items found.")
            return

        for package_name, links in results.items():
            # Determine extraction type from first item
            extraction_type = "JADX"  # Default
            if links:
                first_header = links[0][0]
                if "(Fast)" in first_header:
                    extraction_type = "Fast"

            # Use the same format as directory mode
            print(f"{GREEN}[{package_name}] {extraction_type} extraction: {len(links)} items found{RESET}")

            # Group links by header type (strip source labels for grouping)
            grouped_links = {}
            for header, value in links:
                # Extract base header by removing source labels like "(JADX)" or "(Fast)"
                base_header = re.sub(r"\s*\([^)]+\)$", "", header)

                # Filter out invalid collection names for collection headers
                if "Collection" in base_header:
                    if not FileHandler._is_valid_collection_name(value):
                        continue

                if base_header not in grouped_links:
                    grouped_links[base_header] = []
                grouped_links[base_header].append(value)

            # Print grouped results with bullet-point format
            for header, values in grouped_links.items():
                unique_values = list(
                    dict.fromkeys(values)
                )  # Remove duplicates while preserving order
                if len(unique_values) == 1:
                    print(f"  • {header}: {unique_values[0]}")
                else:
                    print(f"  • {header}: {len(unique_values)} items")
                    for value in unique_values[:3]:  # Show first 3 items
                        print(f"    - {value}")
                    if len(unique_values) > 3:
                        print(f"    ... and {len(unique_values) - 3} more")

    @staticmethod
    def extract_unique_collections_and_documents(
        results: Dict[str, List[Tuple[str, str]]],
    ) -> Tuple[Set[str], Set[str]]:
        """Extract unique collection and document names from extraction results.

        Args:
            results: Dictionary with extraction results

        Returns:
            Tuple of (unique_collections, unique_documents)

        """
        unique_collections = set()
        unique_documents = set()

        for package_name, items in results.items():
            for header, value in items:
                if "Collection" in header:
                    # Filter out invalid collection names
                    if FileHandler._is_valid_collection_name(value):
                        unique_collections.add(value)
                elif "Document" in header:
                    unique_documents.add(value)

        return unique_collections, unique_documents

    @staticmethod
    def save_unique_collections(collections: Set[str], output_file: str) -> None:
        """Save unique collection names to a file."""
        if collections:
            with open(output_file, "w", encoding="utf-8") as f:
                for collection in sorted(collections):
                    f.write(f"{collection}\n")
            print(
                f"Unique collection names saved to {output_file} ({len(collections)} collections)"
            )

    @staticmethod
    def extract_collections_per_package(
        results: Dict[str, List[Tuple[str, str]]],
    ) -> Dict[str, Set[str]]:
        """Extract collection names per package from extraction results.

        Args:
            results: Dictionary with extraction results mapping package names to list of (header, value) tuples

        Returns:
            Dictionary mapping package names to sets of collection names found in that package

        """
        collections_per_package = {}

        for package_name, items in results.items():
            collections = set()
            for header, value in items:
                if "Collection" in header:
                    # Filter out invalid collection names
                    if FileHandler._is_valid_collection_name(value):
                        collections.add(value)

            if collections:
                collections_per_package[package_name] = collections

        return collections_per_package

    @staticmethod
    def save_unique_documents(documents: Set[str], output_file: str) -> None:
        """Save unique document names to a file."""
        if documents:
            with open(output_file, "w", encoding="utf-8") as f:
                for document in sorted(documents):
                    f.write(f"{document}\n")
            print(
                f"Unique document names saved to {output_file} ({len(documents)} documents)"
            )
