"""CLI Module for OpenFirebase

Handles command-line argument parsing and validation for the OpenFirebase tool.
"""

from pathlib import Path
from typing import Optional

import typer
from typer import Option

from .config import DEFAULT_OUTPUT_DIR

# Create the main Typer app
app = typer.Typer(
    help="Extract Firebase items from APK files using JADX decompilation (default) or fast strings.xml parsing",
    no_args_is_help=True,
    rich_markup_mode="markdown",
    context_settings={"help_option_names": ["-h", "--help"]}
)


def validate_input_exclusivity(
    file: Optional[str],
    apk_dir: Optional[str],
    project_id: Optional[str],
    project_id_file: Optional[Path],
    parse_dns_file: Optional[Path],
    resume: Optional[Path],
    resume_auth_file: Optional[Path]
) -> None:
    """Validate that input options are mutually exclusive."""
    input_options = [file, apk_dir, project_id, project_id_file, parse_dns_file, resume, resume_auth_file]
    provided_options = [opt for opt in input_options if opt is not None]

    if len(provided_options) == 0:
        raise typer.BadParameter(
            "At least one input option must be specified: "
            "--file, --apk-dir, --project-id, --project-id-file, --parse-dns-file, --resume, or --resume-auth-file"
        )

    if len(provided_options) > 1:
        option_names = []
        if file: option_names.append("--file")
        if apk_dir: option_names.append("--apk-dir")
        if project_id: option_names.append("--project-id")
        if project_id_file: option_names.append("--project-id-file")
        if parse_dns_file: option_names.append("--parse-dns-file")
        if resume: option_names.append("--resume")
        if resume_auth_file: option_names.append("--resume-auth-file")

        raise typer.BadParameter(
            f"Only one input option can be specified at a time. "
            f"You provided: {', '.join(option_names)}"
        )


def validate_resume_directory(resume_path: Path) -> Path:
    """Validate resume directory and find firebase_items.txt file."""
    if not resume_path.exists():
        raise typer.BadParameter(f"Resume directory not found: {resume_path}")
    if not resume_path.is_dir():
        raise typer.BadParameter(f"Resume path must be a directory: {resume_path}")

    # Look for *_firebase_items.txt files in the directory
    firebase_items_files = list(resume_path.glob("*_firebase_items.txt"))
    if not firebase_items_files:
        raise typer.BadParameter(
            f"No *_firebase_items.txt files found in directory: {resume_path}"
        )
    if len(firebase_items_files) > 1:
        file_list = "\n  ".join([f.name for f in firebase_items_files])
        raise typer.BadParameter(
            f"Multiple *_firebase_items.txt files found in directory: {resume_path}\n  {file_list}\n  "
            f"Please specify a directory with only one firebase_items.txt file"
        )

    return firebase_items_files[0]


def validate_credentials_usage(
    app_id: Optional[str],
    api_key: Optional[str],
    project_id: Optional[str],
    project_id_file: Optional[Path],
    read_config: bool
) -> None:
    """Validate manual credentials usage."""
    if app_id or api_key:
        if not (project_id or project_id_file):
            raise typer.BadParameter(
                "--app-id and --api-key can only be used with --project-id or --project-id-file"
            )

    # Validate scan option combinations
    if (project_id or project_id_file) and read_config:
        if not (app_id and api_key):
            raise typer.BadParameter(
                "--read-config with --project-id or --project-id-file requires both --app-id and --api-key"
            )


def validate_fuzz_collections(fuzz_collections: Optional[Path]) -> None:
    """Validate fuzz collections requirements."""
    if fuzz_collections:
        if not fuzz_collections.exists():
            raise typer.BadParameter(
                f"Wordlist file does not exist: {fuzz_collections}"
            )


def validate_auth_options(
    check_with_auth: bool,
    email: Optional[str],
    password: Optional[str],
    project_id: Optional[str] = None,
    project_id_file: Optional[Path] = None,
    api_key: Optional[str] = None
) -> None:
    """Validate authentication option requirements."""
    if check_with_auth:
        if not email:
            raise typer.BadParameter(
                "--check-with-auth requires --email to be specified"
            )
        if not password:
            raise typer.BadParameter(
                "--check-with-auth requires --password to be specified"
            )

        # Validate project ID scenarios for authentication
        if project_id:
            # Check if multiple project IDs are specified (comma-separated)
            project_ids = [pid.strip() for pid in project_id.split(",") if pid.strip()]
            if len(project_ids) > 1:
                raise typer.BadParameter(
                    "--check-with-auth with --project-id only supports a single project ID. "
                    f"You provided {len(project_ids)} project IDs. "
                    "Each Firebase project requires its own API key for authentication."
                )
            if not api_key:
                raise typer.BadParameter(
                    "--check-with-auth with --project-id requires --api-key to be specified"
                )

        if project_id_file:
            if not api_key:
                raise typer.BadParameter(
                    "--check-with-auth with --project-id-file requires --api-key to be specified"
                )

            # Read and validate project ID file contains only one project
            try:
                with open(project_id_file, encoding="utf-8") as f:
                    project_ids_from_file = [
                        line.strip() for line in f.readlines() if line.strip()
                    ]

                if len(project_ids_from_file) > 1:
                    raise typer.BadParameter(
                        f"--check-with-auth with --project-id-file only supports a single project ID. "
                        f"Your file contains {len(project_ids_from_file)} project IDs. "
                        f"Each Firebase project requires its own API key for authentication. "
                        f"Please use a file with only one project ID or use individual --project-id calls."
                    )
                if len(project_ids_from_file) == 0:
                    raise typer.BadParameter(
                        f"--project-id-file contains no valid project IDs: {project_id_file}"
                    )

            except FileNotFoundError:
                raise typer.BadParameter(
                    f"Project ID file not found: {project_id_file}"
                )
            except typer.BadParameter:
                # Re-raise BadParameter without wrapping it
                raise
            except Exception as e:
                raise typer.BadParameter(
                    f"Error reading project ID file {project_id_file}: {e}"
                )


def validate_remote_config_options(
    scan_config: bool,
    scan_all: bool,
    project_id: Optional[str] = None,
    project_id_file: Optional[Path] = None,
    api_key: Optional[str] = None,
    app_id: Optional[str] = None,
    cert_sha1: Optional[str] = None,
    package_name: Optional[str] = None
) -> None:
    """Validate Remote Config scanning option requirements."""
    if (scan_config or scan_all) and (project_id or project_id_file):
        # Check if cert_sha1 or package_name provided with multiple project IDs
        if (cert_sha1 or package_name) and project_id:
            # Count comma-separated project IDs
            project_count = len([p.strip() for p in project_id.split(",") if p.strip()])
            if project_count > 1:
                print(
                    f"{typer.style('[ERROR]', fg='red')} Cannot use --cert-sha1 or --package-name "
                    f"with multiple project IDs ({project_count} provided). These parameters are "
                    "specific to a single Firebase project/app."
                )
                raise typer.Exit(1)

        if (cert_sha1 or package_name) and project_id_file:
            # Check if project_id_file contains multiple projects
            try:
                with open(project_id_file) as f:
                    lines = [line.strip() for line in f if line.strip()]
                    if len(lines) > 1:
                        print(
                            f"{typer.style('[ERROR]', fg='red')} Cannot use --cert-sha1 or --package-name "
                            f"with multiple project IDs from file ({len(lines)} found). These parameters are "
                            "specific to a single Firebase project/app."
                        )
                        raise typer.Exit(1)
            except Exception as e:
                print(f"{typer.style('[ERROR]', fg='red')} Could not read project ID file: {e}")
                raise typer.Exit(1)


def validate_write_options(
    write_storage: bool,
    write_storage_file: Optional[Path],
    write_firestore: bool,
    write_firestore_value: Optional[str],
    write_rtdb: bool,
    write_rtdb_file: Optional[Path],
    write_all: bool
) -> None:
    """Validate write operation requirements."""
    if write_storage:
        if write_storage_file is None:
            raise typer.BadParameter(
                "--write-storage requires --write-storage-file to be specified"
            )
        if not write_storage_file.exists():
            raise typer.BadParameter(
                f"Storage write file does not exist: {write_storage_file}"
            )
        if not write_storage_file.is_file():
            raise typer.BadParameter(
                f"Storage write path must be a file (not a directory): {write_storage_file}"
            )

    if write_firestore:
        if write_firestore_value is None:
            raise typer.BadParameter(
                "--write-firestore requires --write-firestore-value to be specified"
            )
        if not write_firestore_value.strip():
            raise typer.BadParameter(
                "--write-firestore-value cannot be empty"
            )

    if write_rtdb:
        if write_rtdb_file is None:
            raise typer.BadParameter(
                "--write-rtdb requires --write-rtdb-file to be specified"
            )
        if not write_rtdb_file.exists():
            raise typer.BadParameter(
                f"RTDB write file does not exist: {write_rtdb_file}"
            )
        if not write_rtdb_file.is_file():
            raise typer.BadParameter(
                f"RTDB write path must be a file (not a directory): {write_rtdb_file}"
            )

    if write_all:
        if write_storage_file is None:
            raise typer.BadParameter(
                "--write-all requires --write-storage-file to be specified"
            )
        if not write_storage_file.exists():
            raise typer.BadParameter(
                f"Storage write file does not exist: {write_storage_file}"
            )
        if not write_storage_file.is_file():
            raise typer.BadParameter(
                f"Storage write path must be a file (not a directory): {write_storage_file}"
            )
        if write_rtdb_file is None:
            raise typer.BadParameter(
                "--write-all requires --write-rtdb-file to be specified"
            )
        if not write_rtdb_file.exists():
            raise typer.BadParameter(
                f"RTDB write file does not exist: {write_rtdb_file}"
            )
        if not write_rtdb_file.is_file():
            raise typer.BadParameter(
                f"RTDB write path must be a file (not a directory): {write_rtdb_file}"
            )
        if write_firestore_value is None:
            raise typer.BadParameter(
                "--write-all requires --write-firestore-value to be specified"
            )
        if not write_firestore_value.strip():
            raise typer.BadParameter(
                "--write-firestore-value cannot be empty"
            )


def validate_resume_fast_extract(resume: Optional[Path], fast_extract: bool) -> None:
    """Validate resume and fast extract compatibility."""
    if resume and fast_extract:
        raise typer.BadParameter(
                "--resume cannot be used with --fast-extract (extraction is skipped)"
            )


def validate_exclude_project_id(
    exclude_project_id: Optional[str],
    resume: Optional[Path]
) -> None:
    """Validate exclude project ID can only be used with resume."""
    if exclude_project_id and not resume:
        raise typer.BadParameter(
            "--exclude-project-id can only be used with --resume"
        )


def validate_resume_auth_file_options(
    resume_auth_file: Optional[Path],
    check_with_auth: bool
) -> Optional[Path]:
    """Validate resume auth file options and find auth_data.json file."""
    if not resume_auth_file:
        return None

    if not check_with_auth:
        raise typer.BadParameter("--resume-auth-file requires --check-with-auth")

    if not resume_auth_file.exists():
        raise typer.BadParameter(f"Authentication data path not found: {resume_auth_file}")

    # If it's a directory, look for auth_data.json inside it
    if resume_auth_file.is_dir():
        auth_file = resume_auth_file / "auth_data.json"
        if not auth_file.exists():
            raise typer.BadParameter(f"No auth_data.json file found in directory: {resume_auth_file}")
        return auth_file

    # If it's a file, validate it's a JSON file
    if not resume_auth_file.name.endswith(".json"):
        raise typer.BadParameter("Authentication data file must be a JSON file (.json extension)")

    return resume_auth_file


@app.command()
def main(
    # Input options
    file: Optional[str] = Option(
        None,
        "-f", "--file",
        help="Single APK file to process with JADX decompilation",
        rich_help_panel="Input Options"
    ),
    apk_dir: Optional[str] = Option(
        None,
        "-d", "--apk-dir",
        help="JADX decompilation on directory containing APK files (*.apk)",
        rich_help_panel="Input Options"
    ),
    fast_extract: bool = Option(
        False,
        "-F", "--fast-extract",
        help="Use fast extraction (strings.xml from all /res/values-* directories) instead of full source analysis. Faster but limited.",
        rich_help_panel="Input Options"
    ),
    resume: Optional[Path] = Option(
        None,
        "-r", "--resume",
        help="Resume from existing results folder containing *_firebase_items.txt file",
        rich_help_panel="Input Options"
    ),
    exclude_project_id: Optional[str] = Option(
        None,
        "--exclude-project-id",
        help="Exclude specific project ID(s) when resuming (comma-separated for multiple IDs, can only be used with --resume)",
        rich_help_panel="Input Options"
    ),

    # Output options
    output_dir: str = Option(
        DEFAULT_OUTPUT_DIR,
        "-o", "--output-dir",
        help=f"Output directory for all generated files (default: {DEFAULT_OUTPUT_DIR}/)",
        rich_help_panel="Processing Options"
    ),

    # Read Testing
    read_rtdb: bool = Option(
        False,
        "-rr", "--read-rtdb",
        help="Test Firebase realtime database for unauthorized read access",
        rich_help_panel="Read Testing"
    ),
    read_storage: bool = Option(
        False,
        "-rs", "--read-storage",
        help="Test Firebase storage buckets for unauthorized read access",
        rich_help_panel="Read Testing"
    ),
    read_config: bool = Option(
        False,
        "-rc", "--read-config",
        help="Test Firebase Remote Config for read access",
        rich_help_panel="Read Testing"
    ),
    read_firestore: bool = Option(
        False,
        "-rf", "--read-firestore",
        help="Test Firestore databases for unauthorized read access",
        rich_help_panel="Read Testing"
    ),
    collection_name: Optional[str] = Option(
        None,
        "--collection-name",
        help="Collection name(s) to test with --read-firestore (comma-separated for multiple, defaults to 'users')",
        rich_help_panel="Read Testing"
    ),
    read_all: bool = Option(
        False,
        "-ra", "--read-all",
        help="Read Firebase databases, storage buckets, Remote Config, and Firestore for unauthorized access",
        rich_help_panel="Read Testing"
    ),
    scan_rate: float = Option(
        1.0,
        "-l", "--scan-rate",
        help="Rate limit for scanning (requests per second)",
        min=0.1,
        rich_help_panel="Read Testing"
    ),
    fuzz_collections: Optional[Path] = Option(
        None,
        "--fuzz-collections",
        help="Path to wordlist file for Firestore collection fuzzing when a publicly accessible database is found",
        rich_help_panel="Read Testing"
    ),

    # Write options
    write_storage: bool = Option(
        False,
        "-ws", "--write-storage",
        help="Test write access to Firebase storage buckets (requires --write-storage-file)",
        rich_help_panel="Write Testing"
    ),
    write_storage_file: Optional[Path] = Option(
        None,
        "--write-storage-file",
        help="Path to file to upload when testing storage write access (required with --write-storage)",
        rich_help_panel="Write Testing"
    ),
    write_firestore: bool = Option(
        False,
        "-wf", "--write-firestore",
        help="Test write access to Firestore databases (requires --write-firestore-value)",
        rich_help_panel="Write Testing"
    ),
    write_firestore_value: Optional[str] = Option(
        None,
        "--write-firestore-value",
        help="String value to write when testing Firestore write access (required with --write-firestore)",
        rich_help_panel="Write Testing"
    ),
    write_rtdb: bool = Option(
        False,
        "-wr", "--write-rtdb",
        help="Test write access to Firebase Realtime Database (requires --write-rtdb-file with JSON data)",
        rich_help_panel="Write Testing"
    ),
    write_rtdb_file: Optional[Path] = Option(
        None,
        "--write-rtdb-file",
        help="Path to JSON file containing data to write when testing RTDB write access (required with --write-rtdb)",
        rich_help_panel="Write Testing"
    ),
    write_all: bool = Option(
        False,
        "-wa", "--write-all",
        help="Test write access to Firebase storage buckets, Firestore databases, and Realtime Database (requires --write-storage-file, --write-rtdb-file, and --write-firestore-value)",
        rich_help_panel="Write Testing"
    ),

    # Processing options
    processes: Optional[int] = Option(
        None,
        "-j", "--processes",
        help="Number of processes for concurrent APK processing (default: min(5, CPU count), max: 5)",
        min=1,
        max=20,
        rich_help_panel="Processing Options"
    ),

    # Direct Read Testing
    project_id: Optional[str] = Option(
        None,
        "-pi", "--project-id",
        help="Scan specific Firebase project ID(s) without extraction (comma-separated for multiple IDs)",
        rich_help_panel="Input Options"
    ),
    project_id_file: Optional[Path] = Option(
        None,
        "-pif", "--project-id-file",
        help="Scan Firebase project IDs from a file (one ID per line) without extraction",
        rich_help_panel="Input Options"
    ),
    parse_dns_file: Optional[Path] = Option(
        None,
        "-pdf", "--parse-dns-file",
        help="Parse DNS entries from file and extract Firebase project IDs (outputs IDs without scanning)",
        rich_help_panel="Input Options"
    ),

    # Manual credentials for config scanning
    app_id: Optional[str] = Option(
        None,
        "-i", "--app-id",
        help="Google App ID for Remote Config scanning with --project-id or --project-id-file",
        rich_help_panel="Remote Config Credentials"
    ),
    api_key: Optional[str] = Option(
        None,
        "-k", "--api-key",
        help="Firebase API key for Remote Config scanning with --project-id or --project-id-file",
        rich_help_panel="Remote Config Credentials"
    ),
    cert_sha1: Optional[str] = Option(
        None,
        "--cert-sha1",
        help="Android app certificate SHA-1 hash for Remote Config scanning (extracted from APK if not provided)",
        rich_help_panel="Remote Config Credentials"
    ),
    package_name: Optional[str] = Option(
        None,
        "--package-name",
        help="Android app package name for Remote Config scanning (extracted from APK if not provided)",
        rich_help_panel="Remote Config Credentials"
    ),

    # Proxy configuration
    proxy: Optional[str] = Option(
        None,
        "-x", "--proxy",
        help="Proxy for HTTP requests (format: protocol://host:port, e.g., http://127.0.0.1:8080)",
        rich_help_panel="Processing Options"
    ),
    
    # Timeout configuration
    timeout: Optional[int] = Option(
        None,
        "-t", "--timeout",
        help="Timeout for JADX decompilation in minutes (default: 30 minutes)",
        min=1,
        rich_help_panel="Processing Options"
    ),

    # Authentication options
    check_with_auth: bool = Option(
        False,
        "-C", "--check-with-auth",
        help="For read and write checks returning 401/403, retry with Firebase authentication",
        rich_help_panel="Authentication"
    ),
    email: Optional[str] = Option(
        None,
        "-e", "--email",
        help="Email address for Firebase authentication (required with --check-with-auth)",
        rich_help_panel="Authentication"
    ),
    password: Optional[str] = Option(
        None,
        "-p", "--password",
        help="Password for Firebase authentication (required with --check-with-auth)",
        rich_help_panel="Authentication"
    ),
    resume_auth_file: Optional[Path] = Option(
        None,
        "--resume-auth-file",
        help="Path to auth_data.json file or results directory containing saved authentication data for direct authentication (skips trial-and-error auth process)",
        rich_help_panel="Authentication"
    )
):
    """Extract Firebase items from APK files and scan for unauthorized access.
    
    This tool can extract Firebase configuration from Android APK files using either
    JADX decompilation (default) or fast strings.xml parsing, then scan the discovered
    Firebase services for security misconfigurations.
    """
    # Perform all validations
    validate_input_exclusivity(file, apk_dir, project_id, project_id_file, parse_dns_file, resume, resume_auth_file)
    validate_resume_fast_extract(resume, fast_extract)
    validate_exclude_project_id(exclude_project_id, resume)

    # Handle resume auth file validation and get actual file path
    validated_resume_auth_file = validate_resume_auth_file_options(resume_auth_file, check_with_auth)

    validate_credentials_usage(app_id, api_key, project_id, project_id_file, read_config)
    validate_fuzz_collections(fuzz_collections)
    validate_write_options(write_storage, write_storage_file, write_firestore, write_firestore_value, write_rtdb, write_rtdb_file, write_all)
    validate_auth_options(check_with_auth, email, password, project_id, project_id_file, api_key)
    validate_remote_config_options(read_config, read_all, project_id, project_id_file, api_key, app_id, cert_sha1, package_name)

    # Handle resume file validation
    resume_file = None
    if resume:
        resume_file = validate_resume_directory(resume)

    # Create a namespace object for compatibility with orchestrator interface
    class Args:
        pass

    args = Args()
    args.file = file
    args.apk_dir = apk_dir
    args.fast_extract = fast_extract
    args.resume = str(resume) if resume else None
    args.resume_file = resume_file
    args.output_dir = output_dir
    args.scan_rtdb = read_rtdb
    args.scan_storage = read_storage
    args.scan_config = read_config
    args.scan_firestore = read_firestore
    args.collection_name = collection_name
    args.scan_all = read_all
    args.scan_rate = scan_rate
    args.fuzz_collections = str(fuzz_collections) if fuzz_collections else None
    args.wordlist = str(fuzz_collections) if fuzz_collections else None
    args.write_storage = write_storage
    args.write_storage_file = str(write_storage_file) if write_storage_file else None
    args.write_firestore = write_firestore
    args.write_firestore_value = write_firestore_value
    args.write_rtdb = write_rtdb
    args.write_rtdb_file = str(write_rtdb_file) if write_rtdb_file else None
    args.write_all = write_all
    args.processes = processes
    args.scan_project_id = project_id
    args.scan_project_id_file = str(project_id_file) if project_id_file else None
    args.parse_dns_file = str(parse_dns_file) if parse_dns_file else None
    args.app_id = app_id
    args.api_key = api_key
    args.cert_sha1 = cert_sha1
    args.package_name = package_name
    args.proxy = proxy
    args.check_with_auth = check_with_auth
    args.email = email
    args.password = password
    args.resume_auth_file = str(validated_resume_auth_file) if validated_resume_auth_file else None
    args.exclude_project_id = exclude_project_id
    args.timeout = timeout

    # Import here to avoid circular imports
    from ..core.orchestrator import OpenFirebaseOrchestrator

    # Create and run the orchestrator with the parsed arguments
    orchestrator = OpenFirebaseOrchestrator()
    return orchestrator.run_with_args(args)


