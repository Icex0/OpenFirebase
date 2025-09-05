"""Base Classes for OpenFirebase

Abstract base classes for extractors and scanners.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Tuple


class BaseExtractor(ABC):
    """Abstract base class for all extractors."""

    def __init__(self, input_folder: str):
        """Initialize the extractor with the input folder path."""
        self.input_folder = Path(input_folder)
        self.results: Dict[str, List[Tuple[str, str]]] = {}

    @abstractmethod
    def extract_from_apk(self, apk_path: Path) -> List[Tuple[str, str]]:
        """Extract Firebase items from a single APK file."""

    @abstractmethod
    def get_apk_files(self) -> List[Path]:
        """Get list of APK files to process."""

    def get_results(self) -> Dict[str, List[Tuple[str, str]]]:
        """Get all extraction results."""
        return self.results
