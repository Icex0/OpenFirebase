"""OpenFirebase - Extract Firebase items from APK files."""

# Import from new modular structure
from .extractors import FirebaseExtractor, ProjectIDExtractor
from .handlers import FileHandler
from .main import main
from .parsers import ResultsParser
from .scanners import FirebaseScanner

__version__ = "1.0.0"
__all__ = [
    "FileHandler",
    "FirebaseExtractor",
    "FirebaseScanner",
    "ProjectIDExtractor",
    "ResultsParser",
    "main",
]
