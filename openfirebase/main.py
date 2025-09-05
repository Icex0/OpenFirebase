"""Main Module for OpenFirebase CLI

Entry point for the OpenFirebase tool.
"""

import multiprocessing

from .core.cli import app


def main():
    """Main entry point for the OpenFirebase application."""
    # Required for multiprocessing on Windows and macOS
    multiprocessing.set_start_method("spawn", force=True)
    app()


if __name__ == "__main__":
    main()
