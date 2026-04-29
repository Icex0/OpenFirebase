"""OpenFirebase - Extract Firebase items from APK files."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Import from new modular structure
from .extractors import FirebaseExtractor, ProjectIDExtractor
from .handlers import FileHandler
from .main import main
from .parsers import ResultsParser
from .scanners import FirebaseScanner

# Single source of truth: pyproject.toml. Falls back only when running from a
# source tree without an installed dist-info (rare; dev env without `pip install -e .`).
try:
    __version__ = _pkg_version("openfirebase")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
__all__ = [
    "FileHandler",
    "FirebaseExtractor",
    "FirebaseScanner",
    "ProjectIDExtractor",
    "ResultsParser",
    "main",
]
