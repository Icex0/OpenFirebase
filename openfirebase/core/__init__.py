"""Core module for OpenFirebase.

Contains the main application logic and coordination.
"""

from .base import BaseExtractor
from .config import *

# Note: OpenFirebaseOrchestrator is not imported here to avoid circular imports
# Import it directly as: from openfirebase.core.orchestrator import OpenFirebaseOrchestrator

__all__ = ["BaseExtractor"]
