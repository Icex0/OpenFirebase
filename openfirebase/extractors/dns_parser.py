"""DNS Parser Module

This module parses DNS entries from text files and extracts Firebase project IDs
using regex patterns loaded from firebase_rules.json.
"""

import json
import re
from pathlib import Path
from typing import Dict, Set

try:
    from importlib.resources import files
except ImportError:
    # Fallback for Python < 3.9
    from importlib_resources import files

from ..core.config import DEFAULT_CONFIG_PATH


class DNSParser:
    """Parses DNS entries and extracts Firebase project IDs using patterns from firebase_rules.json."""

    def __init__(self, rules_file: str = None):
        """Initialize DNS parser with Firebase rules.
        
        Args:
            rules_file: Path to firebase_rules.json file. If None, looks for it in the project root.

        """
        self.dns_patterns = self._load_dns_patterns(rules_file)

    def _load_dns_patterns(self, rules_file: str = None) -> Dict[str, str]:
        """Load DNS patterns from firebase_rules.json.
        
        Args:
            rules_file: Path to firebase_rules.json file
            
        Returns:
            Dictionary of pattern names to regex patterns
            
        Raises:
            FileNotFoundError: If firebase_rules.json cannot be found
            ValueError: If the JSON is invalid or missing required patterns

        """
        try:
            if rules_file is None:
                # Load from packaged resource
                package_files = files("openfirebase")
                config_file = package_files / DEFAULT_CONFIG_PATH
                rules_data = json.loads(config_file.read_text(encoding="utf-8"))
            else:
                # Load from file path
                rules_path = Path(rules_file)
                if not rules_path.exists():
                    raise FileNotFoundError(f"Firebase rules file not found: {rules_file}")

                with open(rules_path, encoding="utf-8") as f:
                    rules_data = json.load(f)
        except json.JSONDecodeError as e:
            source = DEFAULT_CONFIG_PATH if rules_file is None else rules_file
            raise ValueError(f"Invalid JSON in {source}: {e}")

        patterns = rules_data.get("patterns", {})
        if not patterns:
            source = DEFAULT_CONFIG_PATH if rules_file is None else rules_file
            raise ValueError(f"No patterns found in {source}")

        # Extract DNS-related patterns
        dns_patterns = {}
        dns_pattern_names = [
            "Firebase_Database_US",
            "Firebase_Database_Other",
            "Firebase_Storage_New",
            "Firebase_Storage_Old"
        ]

        for pattern_name in dns_pattern_names:
            if pattern_name in patterns:
                dns_patterns[pattern_name] = patterns[pattern_name]["pattern"]

        if not dns_patterns:
            raise ValueError("No DNS patterns found in firebase_rules.json")

        return dns_patterns

    def parse_dns_file(self, file_path: str) -> Set[str]:
        """Parse a DNS file and extract unique Firebase project IDs.

        Args:
            file_path: Path to the DNS file to parse

        Returns:
            Set of unique project IDs extracted from the file

        Raises:
            FileNotFoundError: If the file doesn't exist
            PermissionError: If the file can't be read

        """
        dns_file = Path(file_path)
        if not dns_file.exists():
            raise FileNotFoundError(f"DNS file not found: {file_path}")

        project_ids = set()

        try:
            with open(dns_file, encoding="utf-8") as f:
                lines = f.readlines()

            for _, line in enumerate(lines, 1):
                line = line.strip()
                if not line:  # Skip empty lines
                    continue

                # Extract project IDs from this line using all patterns
                extracted_ids = self._extract_project_ids_from_line(line)
                project_ids.update(extracted_ids)

        except PermissionError:
            raise PermissionError(f"Permission denied reading file: {file_path}")
        except UnicodeDecodeError as e:
            raise ValueError(f"Unable to decode file {file_path}: {e}")

        return project_ids

    def _extract_project_ids_from_line(self, line: str) -> Set[str]:
        """Extract project IDs from a single line using DNS patterns.

        Args:
            line: The DNS entry line to parse

        Returns:
            Set of project IDs found in the line

        """
        project_ids = set()

        for pattern_name, pattern in self.dns_patterns.items():
            try:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    if match.groups() and len(match.groups()) > 0:
                        project_id = match.group(1)

                        # Validate project ID format
                        if self._is_valid_project_id(project_id):
                            # Clean up project ID (remove common suffixes)
                            clean_project_id = project_id.replace("-default-rtdb", "")
                            project_ids.add(clean_project_id)

            except re.error:
                # Skip malformed regex (shouldn't happen with our patterns)
                continue

        return project_ids

    def _is_valid_project_id(self, project_id: str) -> bool:
        """Validate if a project ID is valid and not in the exclusion list.

        Args:
            project_id: The project ID to validate

        Returns:
            True if valid, False otherwise

        """
        from ..core.config import INVALID_PROJECT_IDS

        return (
            project_id
            and re.match(r"^[a-z0-9-]+$", project_id)
            and project_id not in INVALID_PROJECT_IDS
            and len(project_id) > 2  # Minimum length check
            and not project_id.startswith("-")  # Don't start with dash
            and not project_id.endswith("-")    # Don't end with dash
        )

    @staticmethod
    def save_project_ids(project_ids: Set[str], output_file: str):
        """Save extracted project IDs to a file.

        Args:
            project_ids: Set of unique project IDs
            output_file: Path to the output file

        """
        with open(output_file, "w", encoding="utf-8") as f:
            for project_id in sorted(project_ids):
                f.write(f"{project_id}\n")

    @staticmethod
    def print_project_ids(project_ids: Set[str], source_file: str):
        """Print extracted project IDs to console.

        Args:
            project_ids: Set of unique project IDs
            source_file: Source DNS file path for display

        """
        from ..core.config import BLUE, ORANGE, RESET

        print("\n" + "=" * 60)
        print(f"{ORANGE}DNS FILE PARSER RESULTS{RESET}")
        print("=" * 60)
        print(f"{BLUE}Source file:{RESET} {source_file}")
        print(f"{BLUE}Project IDs found:{RESET} {len(project_ids)}\\n")

        if project_ids:
            print(f"{ORANGE}Extracted Firebase Project IDs:{RESET}")
            print("-" * 40)
            for project_id in sorted(project_ids):
                print(f"  {project_id}")
        else:
            print("No Firebase project IDs found in the DNS file.")

        print("=" * 60)
