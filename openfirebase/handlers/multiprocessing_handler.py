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

    # Start with the filename stem as the identifier. If process_apk
    # succeeds we'll upgrade to the canonical package name / bundle ID
    # that process_apk already extracts as part of its normal work —
    # that way we avoid parsing the APK twice with androguard just to
    # pre-fetch a name for error reporting.
    package_name = apk_path.stem

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

        # Upgrade the identifier to the canonical name now that
        # process_apk has appended APK_Package_Name (Android) or
        # IPA_Bundle_ID (iOS) to firebase_items. Fall back to the
        # filename stem if neither is present (e.g. parse failure).
        for header, value in firebase_items:
            if header in ("APK_Package_Name", "IPA_Bundle_ID") and value:
                package_name = value
                break

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
