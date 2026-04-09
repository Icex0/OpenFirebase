"""Multiprocessing Handler for OpenFirebase

Handles multiprocessing operations for APK file processing.
"""

import signal
from pathlib import Path

from ..utils import format_firebase_items_status


def process_apk_multiprocessing(args_tuple) -> tuple:
    """Process a single APK/IPA file for multiprocessing.

    Args:
        args_tuple: Tuple containing (apk_path, input_folder, output_file)

    Returns:
        Tuple of (package_name, firebase_items, success, status_message) or
        (package_name, [], False, error, status_message) on failure.

    """
    apk_path_str, input_folder, output_file = args_tuple
    apk_path = Path(apk_path_str)

    from ..utils import get_apk_package_name
    package_name = get_apk_package_name(apk_path)

    def subprocess_signal_handler(_sig, _frame):
        import sys
        sys.exit(0)

    signal.signal(signal.SIGINT, subprocess_signal_handler)
    signal.signal(signal.SIGTERM, subprocess_signal_handler)

    try:
        from .file_handler import FileHandler
        from ..extractors.extractor import FirebaseExtractor

        file_handler = FileHandler()
        extractor = FirebaseExtractor(input_folder)
        firebase_items = extractor.process_apk(apk_path)
        status_msg = format_firebase_items_status(
            package_name, firebase_items, "Fast"
        )

        if firebase_items:
            file_handler.save_single_result(package_name, firebase_items, output_file)

        return (package_name, firebase_items, True, status_msg)
    except (KeyboardInterrupt, SystemExit):
        return (package_name, [], True, f"[{package_name}] Processing interrupted")
    except Exception as e:
        return (package_name, [], False, str(e), f"[{package_name}] Error: {e!s}")
