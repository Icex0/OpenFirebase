"""Results Parser Module

This module contains the ResultsParser class that handles parsing existing
firebase_items.txt files for the --resume functionality.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple


class ResultsParser:
    """Parse existing firebase_items.txt files to resume scanning without re-extraction."""

    def __init__(self, results_file: str):
        """Initialize the parser with the results file path.

        Args:
            results_file: Path to the firebase_items.txt file to parse

        """
        self.results_file = Path(results_file)
        if not self.results_file.exists():
            raise FileNotFoundError(f"Results file not found: {results_file}")

    def parse_results(self) -> Dict[str, List[Tuple[str, str]]]:
        """Parse the firebase_items.txt file and extract Firebase items.

        Returns:
            Dictionary mapping package names to lists of (header, value) tuples

        """
        results = {}
        current_package = None
        current_header = None

        with open(self.results_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Check for package header: === package.name ===
                package_match = re.match(r"^=== (.+) ===$", line)
                if package_match:
                    current_package = package_match.group(1)
                    if current_package not in results:
                        results[current_package] = []
                    continue

                # Check for Firebase item header: [Firebase_Storage_Old]
                header_match = re.match(r"^\[([^\]]+)\]$", line)
                if header_match:
                    current_header = header_match.group(1)
                    continue

                # Check for Firebase item value: - value
                if line.startswith("- ") and current_package and current_header:
                    value = line[2:]  # Remove "- " prefix

                    # Clean up the header by removing source labels like "(JADX)" or "(Fast)"
                    clean_header = self._clean_header(current_header)

                    # Add the item to results
                    results[current_package].append((clean_header, value))

        return results

    def _clean_header(self, header: str) -> str:
        """Clean header by removing source labels like "(JADX)" or "(Fast)".

        Args:
            header: Header string that may contain source labels

        Returns:
            Cleaned header string

        """
        # Remove source labels like "(JADX)", "(Fast)", "(APKLeaks)", etc.
        cleaned = re.sub(r"\s*\([^)]+\)$", "", header)
        return cleaned.strip()

    def get_results(self) -> Dict[str, List[Tuple[str, str]]]:
        """Get parsed results (alias for parse_results for consistency with extractors).

        Returns:
            Dictionary mapping package names to lists of (header, value) tuples

        """
        return self.parse_results()

    def deduplicate_results(
        self, results: Dict[str, List[Tuple[str, str]]]
    ) -> Dict[str, List[Tuple[str, str]]]:
        """Remove duplicate entries within each package while preserving order.

        Args:
            results: Dictionary with extraction results

        Returns:
            Dictionary with deduplicated results

        """
        deduplicated = {}

        for package_name, items in results.items():
            seen = set()
            unique_items = []

            for header, value in items:
                # Create a key for deduplication (header + value)
                key = (header, value)
                if key not in seen:
                    seen.add(key)
                    unique_items.append((header, value))

            if unique_items:
                deduplicated[package_name] = unique_items

        return deduplicated
