"""Multiprocessing Handler for OpenFirebase

Handles multiprocessing operations for APK file processing.
"""

import signal
from pathlib import Path

from ..utils import format_firebase_items_status


def process_apk_multiprocessing(args_tuple) -> tuple:
    """Process a single APK file for multiprocessing.

    Args:
        args_tuple: Tuple containing (apk_path, input_folder, fast_extract, output_file, timeout_seconds)

    Returns:
        Tuple of (package_name, firebase_items, success, [error], status_message)

    """
    apk_path_str, input_folder, fast_extract, output_file, timeout_seconds = args_tuple
    apk_path = Path(apk_path_str)
    
    # Extract real package name
    from ..utils import get_apk_package_name
    package_name = get_apk_package_name(apk_path)

    # Set up signal handler for subprocess to handle Ctrl+C gracefully
    def subprocess_signal_handler(sig, _):
        # Don't raise exceptions - just exit gracefully
        import sys
        sys.exit(0)

    signal.signal(signal.SIGINT, subprocess_signal_handler)
    signal.signal(signal.SIGTERM, subprocess_signal_handler)

    try:
        # Import here to avoid pickling issues
        from .file_handler import FileHandler

        # Create instances in the subprocess
        file_handler = FileHandler()

        if fast_extract:
            from ..extractors.extractor import FirebaseExtractor

            extractor = FirebaseExtractor(input_folder)
            firebase_items = extractor.process_apk(apk_path)
            status_msg = format_firebase_items_status(
                package_name, firebase_items, "Fast"
            )
        else:
            from ..extractors.jadx_extractor import JADXExtractor

            extractor = JADXExtractor(input_folder, processing_mode="directory", timeout_seconds=timeout_seconds)
            firebase_items = extractor.process_file(apk_path)
            status_msg = format_firebase_items_status(
                package_name, firebase_items, "JADX"
            )

        # Save result immediately to avoid data loss
        if firebase_items:
            file_handler.save_single_result(package_name, firebase_items, output_file)

        return (package_name, firebase_items, True, status_msg)
    except (KeyboardInterrupt, SystemExit):
        # Handle gracefully in subprocess - terminate quickly
        return (package_name, [], True, f"[{package_name}] Processing interrupted")
    except Exception as e:
        return (package_name, [], False, str(e), f"[{package_name}] Error: {e!s}")
