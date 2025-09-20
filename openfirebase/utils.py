"""Utility Module for OpenFirebase

Contains utility functions for signal handling, file operations, timestamp management, etc.
"""

import os
import re
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from .core.config import BLUE, GREEN, ORANGE, RED, RESET, VERSION, YELLOW


def create_openfirebase_header():
    """Create a colorized ASCII art header for OpenFirebase with gradient colors."""

    # ASCII art for "OpenFirebase" using slant font
    ascii_lines = [
        "   ____                   _______           __                  ",
        "  / __ \\____  ___  ____  / ____(_)_______  / /_  ____ _________ ",
        " / / / / __ \\/ _ \\/ __ \\/ /_  / / ___/ _ \\/ __ \\/ __ `/ ___/ _ \\",
        "/ /_/ / /_/ /  __/ / / / __/ / / /  /  __/ /_/ / /_/ (__  )  __/",
        "\\____/ .___/\\___/_/ /_/_/   /_/_/   \\___/_.___/\\__,_/____/\\___/ ",
        "    /_/                                                         ",
    ]

    colored_lines = []
    for line in ascii_lines:
        if not line.strip():  # Skip empty lines
            colored_lines.append(line)
            continue

        colored_line = ""
        line_length = len(line)

        for i, char in enumerate(line):
            if char == " ":
                colored_line += char
                continue

            # Calculate position ratio (0.0 to 1.0)
            ratio = i / max(line_length - 1, 1)

            # Apply color based on position (Firebase gradient: red to orange to yellow)
            if ratio < 0.33:
                # Red to Orange (left side)
                colored_line += RED + char + RESET
            elif ratio < 0.66:
                # Orange (middle)
                colored_line += ORANGE + char + RESET
            else:
                # Orange to Yellow (right side)
                colored_line += YELLOW + char + RESET

        colored_lines.append(colored_line)

    # Add attribution lines
    colored_lines.append("")
    colored_lines.append(f"{GREEN}> Tool by: Icex0{RESET}")
    colored_lines.append(
        f"{GREEN}> Research: https://ice0.blog/docs/openfirebase{RESET}"
    )
    colored_lines.append(f"{GREEN}> Version: {VERSION}{RESET}")

    return "\n".join(colored_lines)


# Global variables to handle graceful shutdown
_shutdown_requested = False
_global_executor = None
_extraction_context = None


def signal_handler(sig, _):
    """Handle SIGINT (Ctrl+C) gracefully."""
    global _shutdown_requested, _global_executor, _extraction_context
    _shutdown_requested = True
    print(f"\n{RED}[X]{RESET} Shutdown requested by user (Ctrl+C).")
    print(f"{BLUE}[INF]{RESET} Attempting graceful shutdown - will save extracted data...")

    # Don't force exit immediately - allow graceful shutdown
    # The processing loop will detect the shutdown flag and exit cleanly

    # If we receive multiple Ctrl+C, force shutdown
    if sig == signal.SIGINT:
        signal.signal(signal.SIGINT, lambda _, __: force_shutdown())


def force_shutdown():
    """Force immediate shutdown - used when graceful shutdown fails."""
    global _global_executor, _shutdown_requested
    print(f"\n{RED}[X]{RESET} Force shutdown - terminating processes...")

    # Set shutdown flag to prevent new processes from starting
    _shutdown_requested = True

    # Kill worker processes first, then clean up executor
    if _global_executor is not None:
        try:
            # Kill processes immediately to stop any running tasks
            if (hasattr(_global_executor, "_processes") 
                and _global_executor._processes is not None):
                for process in _global_executor._processes.values():
                    if process.is_alive():
                        process.kill()
                        process.join(timeout=1)
            
            # Then shutdown executor to clean up resources
            _global_executor.shutdown(wait=False)
        except:
            pass

    # Kill any remaining Java processes  
    _kill_java_processes()
    os._exit(1)


def _kill_java_processes():
    """Kill any remaining Java processes related to OpenFirebase."""
    try:
        if os.name == "nt":  # Windows
            _kill_java_processes_windows()
        else:  # Unix-like systems
            _kill_java_processes_unix()
    except:
        pass


def _kill_java_processes_windows():
    """Kill Java processes on Windows using PowerShell (Windows 11 compatible)."""
    try:
        # Use PowerShell to get Java processes with CommandLine and ProcessId
        powershell_cmd = [
            "powershell", "-Command",
            "Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'java.exe'} | "
            "Where-Object {$_.CommandLine -like '*jadx*' -or $_.CommandLine -like '*apksigner*'} | "
            "Select-Object ProcessId | ForEach-Object {$_.ProcessId}"
        ]
        
        result = subprocess.run(
            powershell_cmd,
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            # Kill each process ID returned
            for line in result.stdout.strip().split('\n'):
                pid = line.strip()
                if pid and pid.isdigit():
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", pid], 
                                     capture_output=True, timeout=3)
                    except:
                        pass
    except:
        pass


def _kill_java_processes_unix():
    """Kill Java processes on Unix-like systems."""
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'java' in line and ('jadx' in line.lower() or 'apksigner' in line.lower()):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1])
                            subprocess.run(["kill", "-KILL", str(pid)], 
                                         capture_output=True, timeout=3)
                        except:
                            pass
    except:
        pass


def set_global_executor(executor):
    """Set the global executor for signal handling."""
    global _global_executor
    _global_executor = executor


def is_shutdown_requested():
    """Check if shutdown has been requested."""
    return _shutdown_requested


def load_wordlist(wordlist_path: str) -> Tuple[List[str], bool]:
    """Load collection names from wordlist file.
    
    Args:
        wordlist_path: Path to the wordlist file
        
    Returns:
        Tuple of (wordlist, success_flag)
        - wordlist: List of collection names (empty if failed)
        - success_flag: True if loaded successfully, False otherwise

    """

    try:
        with open(wordlist_path, encoding="utf-8") as f:
            wordlist = [line.strip() for line in f.readlines() if line.strip()]
        print(
            f"{BLUE}[INF]{RESET} Loaded {len(wordlist)} collection names from {wordlist_path}"
        )
        return wordlist, True
    except FileNotFoundError:
        print(f"{YELLOW}[!]{RESET}  Warning: Wordlist file not found: {wordlist_path}")
        print("   Collection fuzzing will be disabled.")
        return [], False
    except Exception as e:
        print(f"{YELLOW}[!]{RESET}  Warning: Error loading wordlist: {e}")
        print("   Collection fuzzing will be disabled.")
        return [], False


def set_extraction_context(context):
    """Set the extraction context for graceful shutdown."""
    global _extraction_context
    _extraction_context = context


def cleanup_executor():
    """Cleanup the global executor."""
    global _global_executor
    if _global_executor is not None:
        try:
            _global_executor.shutdown(wait=True)
        except Exception:
            pass
        _global_executor = None


def create_output_path(output_dir: str, filename: str, timestamp: str = None) -> str:
    """Create output file path in the specified directory with optional timestamp.

    Args:
        output_dir: Base output directory name
        filename: Base filename (e.g., "firebase_items.txt")
        timestamp: Optional timestamp string to prefix both directory and filename

    Returns:
        Full path to output file

    """
    # Get the current working directory
    current_dir = Path.cwd()

    # Resolve output directory relative to the current working directory
    if Path(output_dir).is_absolute():
        # If output_dir is already absolute, use it as-is
        base_output_dir = Path(output_dir)
    else:
        # If output_dir is relative, resolve it relative to the current working directory
        base_output_dir = current_dir / output_dir

    # Apply timestamp to directory name if provided
    if timestamp:
        # Create timestamped directory inside the specified output directory
        timestamped_dir = base_output_dir / f"{timestamp}_results"
    else:
        timestamped_dir = base_output_dir

    # Create output directory if it doesn't exist
    timestamped_dir.mkdir(parents=True, exist_ok=True)

    if timestamp:
        # Split filename and extension
        path = Path(filename)
        name_part = path.stem
        extension = path.suffix
        # Add timestamp prefix to filename as well
        timestamped_filename = f"{timestamp}_{name_part}{extension}"
        return str(timestamped_dir / timestamped_filename)
    return str(timestamped_dir / filename)


def generate_timestamp() -> str:
    """Generate a timestamp string for file naming."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def get_current_datetime() -> str:
    """Generate a human-readable timestamp for logging."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_apk_package_name(apk_path: Path) -> Optional[str]:
    """Extract package name from APK file.
    
    Args:
        apk_path: Path to the APK file
        
    Returns:
        Package name if extraction succeeds, None otherwise
    """
    try:
        # Try using androguard APK.get_package() first
        from androguard.core.apk import APK
        apk = APK(apk_path)
        return apk.get_package()
    except Exception:
        # If androguard fails, fall back to APK filename
        return apk_path.stem


def format_firebase_items_status(
    package_name: str, firebase_items: List[Tuple[str, str]], extraction_type: str
) -> str:
    """Format Firebase items status message similar to final output file format with color coding.

    Args:
        package_name: Name of the APK package
        firebase_items: List of (header, value) tuples
        extraction_type: "Fast" or "JADX"

    Returns:
        Formatted status message string with ANSI color codes

    """

    if not firebase_items:
        # Red color for no items found
        return f"{RED}[{package_name}] {extraction_type} extraction: No Firebase items found{RESET}"

    # Group items by header type (similar to file_handler logic)
    grouped_links = {}
    for header, value in firebase_items:
        # Extract base header by removing source labels like "(JADX)" or "(Fast)"
        base_header = re.sub(r"\s*\([^)]+\)$", "", header)

        if base_header not in grouped_links:
            grouped_links[base_header] = []
        grouped_links[base_header].append(value)

    # Create status message with green color for packages with items
    status_lines = [
        f"{GREEN}[{package_name}] {extraction_type} extraction: {len(firebase_items)} items found{RESET}"
    ]

    for header, values in grouped_links.items():
        unique_values = list(
            dict.fromkeys(values)
        )  # Remove duplicates while preserving order
        if len(unique_values) == 1:
            status_lines.append(f"  • {header}: {unique_values[0]}")
        else:
            status_lines.append(f"  • {header}: {len(unique_values)} items")
            for value in unique_values[:3]:  # Show first 3 items
                status_lines.append(f"    - {value}")
            if len(unique_values) > 3:
                status_lines.append(f"    ... and {len(unique_values) - 3} more")

    return "\n".join(status_lines)


def extract_config_data(results: Dict) -> Dict[str, Dict[str, str]]:
    """Extract Google API key and App ID data from extraction results for config scanning.

    Args:
        results: Dictionary with extraction results from Firebase extractor

    Returns:
        Dictionary mapping project IDs to their config data (api_key, app_id, etc.)

    """
    from .extractors.project_id_extractor import ProjectIDExtractor

    config_data = {}

    for package_name, links in results.items():
        main_project_id = None  # From Firebase_Project_ID field
        explicit_project_ids = []  # Collect Firebase_Project_ID entries in order
        api_keys = []  # Collect ALL Google API keys in order
        app_ids = []   # Collect ALL Google App IDs in order
        cert_sha1_list = []  # Collect all SHA-1 certificates
        apk_package_name = None

        # Extract ALL credentials from the links, preserving order
        for link_type, link_value in links:
            if link_type == "Firebase_Project_ID":
                explicit_project_ids.append(link_value)
                if main_project_id is None:  # First one becomes main
                    main_project_id = link_value
            elif link_type == "Google_API_Key":
                api_keys.append(link_value)  # Collect ALL API keys in order
            elif link_type == "Google_App_ID":
                app_ids.append(link_value)   # Collect Google App IDs in order
            elif link_type == "APK_Certificate_SHA1":
                cert_sha1_list.append(link_value)  # Collect all certificates
            elif link_type == "APK_Package_Name":
                apk_package_name = link_value

        # Get ALL project IDs from this package (including ones from URLs)
        all_project_ids = ProjectIDExtractor.extract_project_ids_from_urls(links)
        
        # Use positional mapping: match by index position
        # The 1st project ID gets the 1st API key and 1st App ID, etc.
        explicit_project_list = list(explicit_project_ids)
        
        # Create consistent ordered list: explicit project IDs first (in original order),
        # then additional project IDs from URLs (sorted for consistency)
        additional_project_ids = sorted(all_project_ids - set(explicit_project_ids))
        ordered_project_ids = explicit_project_list + additional_project_ids
        
        for project_id in ordered_project_ids:
            if project_id not in config_data:
                config_data[project_id] = {}

            # Find the index of this project_id in the explicit list
            project_index = None
            try:
                project_index = explicit_project_list.index(project_id)
            except ValueError:
                # Project ID not in explicit list (extracted from URLs)
                # Assign remaining credentials if any are unused
                used_indices = set()
                for existing_pid in config_data:
                    if existing_pid in explicit_project_list:
                        used_indices.add(explicit_project_list.index(existing_pid))
                
                # Find first unused index
                for i in range(max(len(api_keys), len(app_ids))):
                    if i not in used_indices:
                        project_index = i
                        break

            # Assign credentials based on positional index
            if project_index is not None:
                if project_index < len(api_keys):
                    config_data[project_id]["api_key"] = api_keys[project_index]
                if project_index < len(app_ids):
                    config_data[project_id]["app_id"] = app_ids[project_index]

            # Add certificates and package_name to ALL project IDs from the same APK
            # since they all come from the same Android app with the same certificate
            if cert_sha1_list:
                # Add legacy cert_sha1 for backward compatibility (first certificate)
                config_data[project_id]["cert_sha1"] = cert_sha1_list[0]
                # Add new cert_sha1_list for multiple certificate support
                config_data[project_id]["cert_sha1_list"] = cert_sha1_list.copy()

            # Use APK package name if available, otherwise fall back to APK filename
            if apk_package_name:
                config_data[project_id]["package_name"] = apk_package_name
            else:
                # Fallback to using the APK filename (results key) as package name
                config_data[project_id]["package_name"] = package_name

    return config_data


def extract_enhanced_auth_data(results: Dict) -> Dict[str, Dict]:
    """Extract authentication data with enhanced key selection logic.
    
    Uses google_api_key for Firebase_Project_ID and Other_Google_API_Key for other projects.
    
    Args:
        results: Dictionary with extraction results from Firebase extractor
        
    Returns:
        Dictionary mapping project IDs to their auth data:
        {
            'project_id': {
                'main_project_id': str,  # The Firebase_Project_ID if this is the main project
                'api_keys': List[str],   # List of API keys to try
                'cert_sha1': str,       # Certificate if available 
                'package_name': str     # Package name if available
            }
        }

    """
    from .extractors.project_id_extractor import ProjectIDExtractor

    auth_data = {}

    for package_name, links in results.items():
        main_project_id = None  # From Firebase_Project_ID field
        explicit_project_ids = []  # Collect Firebase_Project_ID entries in order
        google_api_keys = []    # Collect ALL Google_API_Key entries in order
        other_api_keys = []     # From Other_Google_API_Key fields
        app_ids = []            # Collect ALL Google_App_ID entries in order
        cert_sha1_list = []     # Collect all SHA-1 certificates
        apk_package_name = None

        # Extract ALL credentials from the links, preserving order
        for link_type, link_value in links:
            if link_type == "Firebase_Project_ID":
                explicit_project_ids.append(link_value)
                if main_project_id is None:  # First one becomes main
                    main_project_id = link_value
            elif link_type == "Google_API_Key":
                google_api_keys.append(link_value)  # Collect ALL API keys in order
            elif link_type == "Other_Google_API_Key":
                other_api_keys.append(link_value)
            elif link_type == "Google_App_ID":
                app_ids.append(link_value)  # Collect ALL App IDs in order
            elif link_type == "Other_Google_App_ID":
                app_ids.append(link_value)  # Collect other Google App IDs too
            elif link_type == "APK_Certificate_SHA1":
                cert_sha1_list.append(link_value)  # Collect all certificates
            elif link_type == "APK_Package_Name":
                apk_package_name = link_value

        # Get ALL project IDs from this package (including ones from URLs)
        all_project_ids = ProjectIDExtractor.extract_project_ids_from_urls(links)
        
        # Use positional mapping: match by index position
        # The 1st project ID gets the 1st API key and 1st App ID, etc.
        explicit_project_list = list(explicit_project_ids)

        # Create consistent ordered list: explicit project IDs first (in original order),
        # then additional project IDs from URLs (sorted for consistency)
        additional_project_ids = sorted(all_project_ids - set(explicit_project_ids))
        ordered_project_ids = explicit_project_list + additional_project_ids

        # Create auth entries for all project IDs found
        for project_id in ordered_project_ids:
            if project_id not in auth_data:
                auth_data[project_id] = {
                    "main_project_id": None,
                    "api_keys": [],
                    "app_id": None,
                    "cert_sha1_list": [],  # List of all SHA-1 certificates
                    "package_name": None
                }

            # Find the index of this project_id in the explicit list
            project_index = None
            try:
                project_index = explicit_project_list.index(project_id)
            except ValueError:
                # Project ID not in explicit list (extracted from URLs)
                # Assign remaining credentials if any are unused
                used_indices = set()
                for existing_pid in auth_data:
                    if existing_pid in explicit_project_list:
                        used_indices.add(explicit_project_list.index(existing_pid))
                
                # Find first unused index
                for i in range(len(google_api_keys)):
                    if i not in used_indices:
                        project_index = i
                        break

            # Assign credentials based on positional index
            if project_id == main_project_id:
                # This is the main project ID (Firebase_Project_ID)
                # Use google_api_key for main project
                auth_data[project_id]["main_project_id"] = main_project_id
                if project_index is not None and project_index < len(google_api_keys):
                    auth_data[project_id]["api_keys"] = [google_api_keys[project_index]]

                # Add additional fields for main project
                if project_index is not None and project_index < len(app_ids):
                    auth_data[project_id]["app_id"] = app_ids[project_index]
            else:
                # This is another project ID (not the main Firebase_Project_ID)
                # Use positional Google_API_Key for non-main projects, fallback to Other_Google_API_Key
                api_keys_to_use = []
                if project_index is not None and project_index < len(google_api_keys):
                    api_keys_to_use.append(google_api_keys[project_index])
                # Always add Other_Google_API_Key keys as fallback options for non-main projects
                if other_api_keys:
                    api_keys_to_use.extend(other_api_keys)
                
                auth_data[project_id]["api_keys"] = api_keys_to_use

                # Also assign app_id positionally for other projects
                if project_index is not None and project_index < len(app_ids):
                    auth_data[project_id]["app_id"] = app_ids[project_index]

            # Add certificate and package name to ALL project IDs from the same APK
            # since they all come from the same Android app with the same certificate
            if cert_sha1_list:
                auth_data[project_id]["cert_sha1_list"] = cert_sha1_list.copy()

            # Use APK package name if available, otherwise fall back to APK filename
            if apk_package_name:
                auth_data[project_id]["package_name"] = apk_package_name
            else:
                auth_data[project_id]["package_name"] = package_name

    return auth_data


def validate_project_ids(project_ids_input):
    """Validate and filter project IDs."""
    from .core.config import INVALID_PROJECT_IDS

    project_ids_set = set()
    for pid in project_ids_input:
        # Validate project ID format and filter out invalid ones
        if re.match(r"^[a-z0-9-]+$", pid) and pid not in INVALID_PROJECT_IDS:
            # Remove "-default-rtdb" suffix if present
            clean_project_id = pid.replace("-default-rtdb", "")
            project_ids_set.add(clean_project_id)
        else:
            print(f"Warning: Skipping invalid project ID: {pid}")

    return project_ids_set


def get_apk_files(input_folder: Path) -> List[Path]:
    """Get all APK files from the input folder.
    
    Args:
        input_folder: Path to folder containing APK files
        
    Returns:
        List of APK file paths sorted by size (smallest first)
    """
    
    if not input_folder.exists():
        raise FileNotFoundError(f"Folder not found: {input_folder}")

    # Find all APK files
    apk_files = list(input_folder.glob("*.apk"))

    if not apk_files:
        # Check if the user provided a single APK file instead of a directory
        if (
            input_folder.is_file()
            and input_folder.suffix.lower() == ".apk"
        ):
            print(f"{RED}[ERROR]{RESET} '{input_folder}' is a single APK file.")
            print(f"{RED}[ERROR]{RESET} Use -f/--file for single APK files, or -d/--apk-dir for directories containing APK files.")
        else:
            print(f"{RED}[ERROR]{RESET} No APK files found in {input_folder}")
        return []

    # Sort files by size (smallest first, largest last)
    apk_files.sort(key=lambda x: x.stat().st_size)

    return apk_files


def cleanup_executor():
    """Clean up the global executor."""
    global _global_executor

    if _global_executor is not None:
        try:
            # Try with timeout (Python 3.9+)
            try:
                _global_executor.shutdown(wait=True, timeout=5.0)
            except TypeError:
                # Fallback for older Python versions that don't support timeout
                _global_executor.shutdown(wait=True)
        except Exception as e:
            print(f"Warning: Error during executor cleanup: {e}")
        finally:
            _global_executor = None



