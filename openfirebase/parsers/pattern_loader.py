"""Pattern Loader Module for OpenFirebase

Loads Firebase detection patterns from configuration files.
"""

import json
from pathlib import Path
from typing import Dict, List

try:
    from importlib.resources import files
except ImportError:
    # Fallback for Python < 3.9
    from importlib_resources import files

from ..core.config import DEFAULT_CONFIG_PATH


class FirebasePatternLoader:
    """Loads and manages Firebase detection patterns from configuration files."""

    def __init__(self, config_path: str = None):
        """Initialize the pattern loader.

        Args:
            config_path: Path to the configuration file. If None, uses packaged resource.

        """
        self.config_path = None
        self._use_resource = False
        
        if config_path is None:
            # Use packaged resource
            self._use_resource = True
        else:
            self.config_path = Path(config_path)

        self._patterns = None
        self._invalid_prefixes = None

    def load_patterns(self) -> Dict[str, str]:
        """Load Firebase patterns from the configuration file.

        Returns:
            Dictionary mapping pattern names to regex strings

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            json.JSONDecodeError: If the configuration file is invalid JSON

        """
        if self._patterns is not None:
            return self._patterns

        try:
            if self._use_resource:
                # Load from packaged resource
                package_files = files("openfirebase")
                config_file = package_files / DEFAULT_CONFIG_PATH
                config = json.loads(config_file.read_text(encoding="utf-8"))
            else:
                # Load from file path
                if not self.config_path.exists():
                    raise FileNotFoundError(
                        f"Firebase rules configuration file not found: {self.config_path}"
                    )
                
                with open(self.config_path, encoding="utf-8") as f:
                    config = json.load(f)

            # Extract patterns from the configuration
            patterns = {}
            for name, pattern_config in config.get("patterns", {}).items():
                if isinstance(pattern_config, dict):
                    patterns[name] = pattern_config["pattern"]
                else:
                    # Fallback for simple string patterns
                    patterns[name] = pattern_config

            self._patterns = patterns
            return patterns

        except json.JSONDecodeError as e:
            source = DEFAULT_CONFIG_PATH if self._use_resource else str(self.config_path)
            raise json.JSONDecodeError(
                f"Invalid JSON in configuration file {source}: {e}"
            )
        except Exception as e:
            source = DEFAULT_CONFIG_PATH if self._use_resource else str(self.config_path)
            raise Exception(f"Error loading patterns from {source}: {e}")

    def get_invalid_collection_prefixes(self) -> List[str]:
        """Get the list of invalid collection name prefixes.

        Returns:
            List of prefixes that should be filtered out from collection names

        """
        if self._invalid_prefixes is not None:
            return self._invalid_prefixes

        try:
            if self._use_resource:
                # Load from packaged resource
                package_files = files("openfirebase")
                config_file = package_files / DEFAULT_CONFIG_PATH
                config = json.loads(config_file.read_text(encoding="utf-8"))
            else:
                # Load from file path
                if not self.config_path.exists():
                    # Return default prefixes if config file doesn't exist
                    return ["Describe protocol", "_tdc", ".append("]
                
                with open(self.config_path, encoding="utf-8") as f:
                    config = json.load(f)

            prefixes = config.get("filtering", {}).get(
                "invalid_collection_prefixes", []
            )
            self._invalid_prefixes = prefixes
            return prefixes

        except (json.JSONDecodeError, Exception):
            # Return default prefixes if there's any error
            return ["Describe protocol", "_tdc", ".append("]

    def get_pattern_info(self) -> Dict:
        """Get full pattern information including descriptions.

        Returns:
            Dictionary with pattern information

        """
        try:
            if self._use_resource:
                # Load from packaged resource
                package_files = files("openfirebase")
                config_file = package_files / DEFAULT_CONFIG_PATH
                config = json.loads(config_file.read_text(encoding="utf-8"))
            else:
                # Load from file path
                if not self.config_path.exists():
                    return {}
                
                with open(self.config_path, encoding="utf-8") as f:
                    config = json.load(f)
            return config.get("patterns", {})
        except:
            return {}


# Global pattern loader instance
_pattern_loader = None


def get_firebase_patterns() -> Dict[str, str]:
    """Get Firebase patterns using the global pattern loader.

    Returns:
        Dictionary mapping pattern names to regex strings

    Raises:
        FileNotFoundError: If firebase_rules.json is not found
        json.JSONDecodeError: If firebase_rules.json contains invalid JSON
        Exception: If there's any other error loading patterns

    """
    global _pattern_loader

    if _pattern_loader is None:
        _pattern_loader = FirebasePatternLoader()

    # No fallback - fail clearly if config is missing or invalid
    return _pattern_loader.load_patterns()


def get_pattern_metadata() -> Dict[str, Dict]:
    """Get full pattern metadata including capture groups from firebase_rules.json.

    Returns:
        Dictionary mapping pattern names to their full configuration

    """
    global _pattern_loader

    if _pattern_loader is None:
        _pattern_loader = FirebasePatternLoader()

    return _pattern_loader.get_pattern_info()


def get_invalid_collection_prefixes() -> List[str]:
    """Get invalid collection name prefixes using the global pattern loader.

    Returns:
        List of prefixes that should be filtered out

    """
    global _pattern_loader

    if _pattern_loader is None:
        _pattern_loader = FirebasePatternLoader()

    return _pattern_loader.get_invalid_collection_prefixes()
