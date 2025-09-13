"""Orchestrator Module for OpenFirebase

Handles the main application workflow and coordinates different components.
"""

import multiprocessing
import signal
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, TimeoutError, as_completed
from pathlib import Path

from tqdm import tqdm

from ..extractors.dns_parser import DNSParser
from ..extractors.extractor import ANDROGUARD_AVAILABLE, FirebaseExtractor
from ..extractors.jadx_extractor import JADXExtractor
from ..extractors.project_id_extractor import ProjectIDExtractor
from ..handlers.file_handler import FileHandler
from ..handlers.multiprocessing_handler import process_apk_multiprocessing
from ..parsers.results_parser import ResultsParser
from ..scanners import FirebaseScanner
from ..utils import (
    cleanup_executor,
    create_openfirebase_header,
    create_output_path,
    extract_config_data,
    extract_enhanced_auth_data,
    generate_timestamp,
    get_current_datetime,
    is_shutdown_requested,
    set_extraction_context,
    set_global_executor,
    signal_handler,
    validate_project_ids,
)
from .config import BLUE, GREEN, ORANGE, RED, RESET, YELLOW


class OpenFirebaseOrchestrator:
    """Main orchestrator for the OpenFirebase application."""

    def __init__(self):
        self.run_timestamp = generate_timestamp()

    def _check_java_availability(self):
        """Check if Java is available for JADX and apksigner tools."""
        try:
            # Try to run java -version to check if Java is installed
            result = subprocess.run(
                ["java", "-version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False


    def run_with_args(self, args):
        """Run the application with already-parsed arguments."""
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)

        # Check for androguard dependency
        if not ANDROGUARD_AVAILABLE:
            print(
                f"{RED}[ERROR]{RESET} androguard is required but not available. "
                "Try reinstalling with: pipx reinstall openfirebase"
            )
            return 1

        # Check for Java availability for JADX and apksigner tools
        if not self._check_java_availability():
            print(
                f"{RED}[ERROR]{RESET} Java is not installed or not available in PATH. "
                "JADX decompilation and remote config scanning will not work without Java. "
            )

        try:
            # Determine number of processes for APK processing
            process_count = self._get_process_count(args.processes)

            # Initialize components
            file_handler = FileHandler()

            # Display OpenFirebase header
            print(f"\n{create_openfirebase_header()}\n")

            # Print start timestamp for all operations
            print(f"{BLUE}[INF]{RESET} {get_current_datetime()}")

            # Route to appropriate workflow
            if args.resume:
                return self._handle_resume_mode(args, file_handler)
            if args.resume_auth_file:
                return self._handle_resume_auth_file_mode(args)
            if args.scan_project_id:
                return self._handle_scan_project_id_mode(args)
            if args.scan_project_id_file:
                return self._handle_scan_project_id_file_mode(args)
            if args.parse_dns_file:
                return self._handle_parse_dns_file_mode(args)
            return self._handle_extraction_mode(args, file_handler, process_count)

        except Exception as e:
            print(f"Error: {e}")
            return 1

    def _get_process_count(self, processes_arg):
        """Determine the number of processes to use."""
        if processes_arg is None:
            # Limit to 5 processes for JADX to avoid overwhelming the system
            return min(5, multiprocessing.cpu_count())
        # Still enforce maximum of 5 for JADX processing
        return min(5, max(1, processes_arg))  # Ensure at least 1, max 5 processes

    def _handle_resume_mode(self, args, file_handler):
        """Handle --resume mode (resume from existing results file)."""
        print(f"{BLUE}[INF]{RESET} Resuming from results directory: {args.resume}")
        print(
            f"{BLUE}[INF]{RESET} Found firebase_items.txt file: {args.resume_file.name}"
        )
        print(
            f"{BLUE}[INF]{RESET} Skipping extraction phase - parsing existing Firebase items..."
        )

        try:
            # Parse existing results
            results_parser = ResultsParser(args.resume_file)
            results = results_parser.parse_results()

            # Deduplicate results
            results = results_parser.deduplicate_results(results)

            print(
                f"\n{BLUE}[INF]{RESET} Parsed Firebase items from {len(results)} package(s):"
            )
            file_handler.print_results(results)

            # Extract project IDs for scanning
            print(f"\n{BLUE}[INF]{RESET} Extracting Firebase project IDs...")
            project_id_extractor = ProjectIDExtractor()
            package_project_ids = project_id_extractor.extract_project_ids_from_results(
                results
            )

            if package_project_ids:
                project_id_extractor.print_project_ids(package_project_ids)

                # Get all unique project IDs for scanning
                all_project_ids = set()
                for pids in package_project_ids.values():
                    all_project_ids.update(pids)

                # Filter out excluded project IDs if specified
                if args.exclude_project_id:
                    excluded_ids = {pid.strip() for pid in args.exclude_project_id.split(",") if pid.strip()}
                    if excluded_ids:
                        original_count = len(all_project_ids)
                        all_project_ids = all_project_ids - excluded_ids
                        excluded_found = excluded_ids.intersection({pid for pids in package_project_ids.values() for pid in pids})

                        if excluded_found:
                            print(f"\n{YELLOW}[WARN]{RESET} Excluded {len(excluded_found)} project ID(s): {', '.join(sorted(excluded_found))}")
                            print(f"{BLUE}[INF]{RESET} Scanning {len(all_project_ids)} project ID(s) (originally {original_count})")
                        else:
                            print(f"\n{YELLOW}[WARN]{RESET} None of the specified exclude project IDs were found in the results")
                    else:
                        print(f"\n{YELLOW}[WARN]{RESET} --exclude-project-id specified but no valid project IDs provided")

                # Extract collections per package for Firestore scanning
                collections_per_package = (
                    file_handler.extract_collections_per_package(results)
                )



                # Continue with scanning if scan options are enabled (read or write)
                if (
                    args.scan_rtdb
                    or args.scan_storage
                    or args.scan_all
                    or args.scan_config
                    or args.scan_firestore
                    or args.write_storage
                    or args.write_firestore
                    or args.write_rtdb
                    or args.write_all
                ):
                    self._perform_scanning(
                        args,
                        all_project_ids,
                        package_project_ids,
                        results,
                        collections_per_package,
                    )
                else:
                    print(
                        "\nNo testing options specified. Use --read-all, --read-rtdb, --read-storage, --read-firestore, --read-config, or write testing options (--write-storage, --write-firestore, --write-rtdb, --write-all) to scan the extracted Firebase resources."
                    )
            else:
                print("No Firebase project IDs found in results.")

            return 0

        except Exception as e:
            print(f"Error parsing results file: {e}")
            return 1

    def _handle_resume_auth_file_mode(self, args):
        """Handle --resume-auth-file mode (scanning with saved authentication data)."""
        from ..handlers.auth_data_handler import AuthDataHandler

        print(f"{BLUE}[INF]{RESET} Resuming with authentication data file: {args.resume_auth_file}")

        # Load authentication data
        auth_data = AuthDataHandler.load_auth_data(args.resume_auth_file)
        if not auth_data:
            print(f"{RED}[ERROR]{RESET} Failed to load authentication data from {args.resume_auth_file}")
            return 1

        # Extract project IDs from auth data
        project_ids_set = set(AuthDataHandler.get_validated_project_ids(auth_data))
        if not project_ids_set:
            print(f"{RED}[ERROR]{RESET} No valid project IDs found in authentication data")
            return 1

        print(f"{BLUE}[INF]{RESET} Found {len(project_ids_set)} project ID(s) with saved authentication data: {', '.join(sorted(project_ids_set))}")

        # Check if any scan options are specified
        has_specific_scan_flags = (
            args.scan_rtdb
            or args.scan_storage
            or args.scan_firestore
            or args.scan_config
            or args.scan_all
        )
        write_flags = args.write_storage or args.write_firestore or args.write_rtdb or args.write_all

        if not has_specific_scan_flags and not write_flags:
            print(
                f"\n{YELLOW}[WARNING]{RESET} No testing options specified. Use --read-all, --read-rtdb, --read-storage, --read-firestore, --read-config, or write testing options (--write-storage, --write-firestore, --write-rtdb, --write-all) to scan the projects."
            )
            return 1

        # Initialize Firebase authentication
        firebase_auth = None
        if getattr(args, "check_with_auth", False):
            from ..core.auth import FirebaseAuth
            firebase_auth = FirebaseAuth(timeout=10, proxy=args.proxy)
            print(f"{BLUE}[INF]{RESET} Authentication enabled - using saved authentication data")

            # Set up authentication tokens using saved data
            successful_auths = 0
            failed_auths = 0

            for project_id in project_ids_set:
                auth_config = AuthDataHandler.get_auth_config_for_project(auth_data, project_id)
                if auth_config:
                    # Create authentication token using saved data
                    token = firebase_auth.create_account_and_get_token(
                        project_id=project_id,
                        api_key=auth_config["api_key"],
                        email=args.email,
                        password=args.password,
                        package_name=auth_config.get("package_name"),
                        cert_sha1=auth_config.get("cert_sha1")
                    )

                    if token:
                        successful_auths += 1
                        print(f"{GREEN}[AUTH]{RESET} Successfully authenticated project {project_id} using saved auth data")
                    else:
                        failed_auths += 1
                        print(f"{RED}[AUTH]{RESET} Failed to authenticate project {project_id} with saved auth data")
                else:
                    failed_auths += 1
                    print(f"{YELLOW}[AUTH]{RESET} No saved authentication data for project {project_id}")

            print(f"\n{BLUE}[AUTH]{RESET} Authentication completed: {successful_auths} successful, {failed_auths} failed")

        # Initialize scanner and perform scanning
        scanner = FirebaseScanner(
            rate_limit=args.scan_rate,
            fuzz_collections_wordlist=args.wordlist,
            proxy=args.proxy,
            firebase_auth=firebase_auth,
        )

        return self._perform_project_id_based_scanning(args, scanner, project_ids_set, firebase_auth)

    def _handle_scan_project_id_mode(self, args):
        """Handle --project-id mode (scanning without extraction)."""
        # Only show the warning if no specific scan flags are provided and we're doing default scanning
        has_specific_scan_flags = (
            args.scan_rtdb
            or args.scan_storage
            or args.scan_firestore
            or args.scan_config
            or args.scan_all
        )
        has_manual_credentials = bool(args.app_id and args.api_key)
        write_firestore = getattr(args, "write_firestore", False) or getattr(args, "write_all", False)

        if not args.write_storage and not write_firestore and not args.write_all and not has_specific_scan_flags:
            if not has_manual_credentials:
                print(
                    f"{YELLOW}[WARNING]{RESET} NOTE: Remote Config scanning is not available with --project-id because it requires Google API keys extracted from APK files."
                )
                print(
                    "   Database, storage, and Firestore scanning will be performed by default.\n"
                )
        elif args.scan_config and not has_manual_credentials:
            print(
                f"{YELLOW}[WARNING]{RESET} NOTE: Remote Config scanning is not available with --project-id because it requires Google API keys extracted from APK files."
            )
            print("   --read-config will be ignored.\n")
        elif args.scan_all and not has_manual_credentials:
            print(
                f"{ORANGE}[WARNING]{RESET} Remote Config scanning is not performed unless --app-id and --api-key are manually provided with --project-id."
            )

        # Parse project IDs (comma-separated)
        project_ids_input = [
            pid.strip() for pid in args.scan_project_id.split(",") if pid.strip()
        ]

        if not project_ids_input:
            print("Error: No valid project IDs provided")
            return 1

        # Filter out invalid project IDs
        project_ids_set = validate_project_ids(project_ids_input)

        if not project_ids_set:
            print("Error: No valid project IDs found after filtering")
            return 1

        print(
            f"{BLUE}[INF]{RESET} Scanning {len(project_ids_set)} project ID(s): {', '.join(sorted(project_ids_set))}"
        )

        # Initialize Firebase authentication if requested
        firebase_auth = None
        if getattr(args, "check_with_auth", False):
            from ..core.auth import FirebaseAuth
            firebase_auth = FirebaseAuth(timeout=10, proxy=args.proxy)
            print(f"{BLUE}[INF]{RESET} Authentication enabled - will retry 403 responses with Firebase auth")

            # Warn if cert_sha1 or package_name are missing for project ID mode
            if not getattr(args, "cert_sha1", None):
                print(f"{YELLOW}[WARNING]{RESET} --cert-sha1 not provided. Authenticated scanning may fail without Android certificate SHA-1 hash.")
            if not getattr(args, "package_name", None):
                print(f"{YELLOW}[WARNING]{RESET} --package-name not provided. Authenticated scanning may fail without Android package name.")

        # Initialize scanner and perform scanning
        scanner = FirebaseScanner(
            rate_limit=args.scan_rate,
            fuzz_collections_wordlist=args.wordlist,
            proxy=args.proxy,
            firebase_auth=firebase_auth,
        )

        return self._perform_project_id_based_scanning(args, scanner, project_ids_set, firebase_auth)

    def _handle_scan_project_id_file_mode(self, args):
        """Handle --project-id-file mode (scanning from file without extraction)."""
        has_manual_credentials = bool(args.app_id and args.api_key)

        # Check for specific scan flags to provide appropriate warnings
        has_specific_scan_flags = (
            args.scan_rtdb
            or args.scan_storage
            or args.scan_firestore
            or args.scan_config
            or args.scan_all
        )
        write_firestore = getattr(args, "write_firestore", False) or getattr(args, "write_all", False)

        if not args.write_storage and not write_firestore and not args.write_all and not has_specific_scan_flags:
            if not has_manual_credentials:
                print(
                    f"{YELLOW}[WARNING]{RESET} NOTE: Remote Config scanning is not available with --project-id-file because it requires Google API keys extracted from APK files."
                )
                print(
                    "   Database, storage, and Firestore scanning will be performed by default.\n"
                )
        elif args.scan_config and not has_manual_credentials:
            print(
                f"{YELLOW}[WARNING]{RESET} NOTE: Remote Config scanning is not available with --project-id-file because it requires Google API keys extracted from APK files."
            )
            print("   --read-config will be ignored.\n")
        elif args.scan_all and not has_manual_credentials:
            print(
                f"{ORANGE}[WARNING]{RESET} Remote Config scanning is not performed unless --app-id and --api-key are manually provided with --project-id-file."
            )

        # Read project IDs from file
        try:
            with open(args.scan_project_id_file, encoding="utf-8") as f:
                project_ids_from_file = [
                    line.strip() for line in f.readlines() if line.strip()
                ]
        except FileNotFoundError:
            print(f"Error: File not found: {args.scan_project_id_file}")
            return 1
        except Exception as e:
            print(f"Error reading file {args.scan_project_id_file}: {e}")
            return 1

        if not project_ids_from_file:
            print("Error: No project IDs found in the file")
            return 1

        # Filter out invalid project IDs
        project_ids_set = validate_project_ids(project_ids_from_file)

        if not project_ids_set:
            print("Error: No valid project IDs found after filtering")
            return 1

        print(
            f"{BLUE}[INF]{RESET} Loaded {len(project_ids_set)} project ID(s) from {args.scan_project_id_file}: {', '.join(sorted(list(project_ids_set)[:5]))}"
            + ("..." if len(project_ids_set) > 5 else "")
        )

        # Initialize Firebase authentication if requested
        firebase_auth = None
        if getattr(args, "check_with_auth", False):
            from ..core.auth import FirebaseAuth
            firebase_auth = FirebaseAuth(timeout=10, proxy=args.proxy)
            print(f"{BLUE}[INF]{RESET} Authentication enabled - will retry 403 responses with Firebase auth")

            # Warn if cert_sha1 or package_name are missing for project ID file mode
            if not getattr(args, "cert_sha1", None):
                print(f"{YELLOW}[WARNING]{RESET} --cert-sha1 not provided. Authenticated scanning may fail without Android certificate SHA-1 hash.")
            if not getattr(args, "package_name", None):
                print(f"{YELLOW}[WARNING]{RESET} --package-name not provided. Authenticated scanning may fail without Android package name.")

        # Initialize scanner
        scanner = FirebaseScanner(
            rate_limit=args.scan_rate,
            fuzz_collections_wordlist=args.wordlist,
            proxy=args.proxy,
            firebase_auth=firebase_auth,
        )

        return self._perform_project_id_based_scanning(args, scanner, project_ids_set, firebase_auth)

    def _handle_parse_dns_file_mode(self, args):
        """Handle --parse-dns-file mode (DNS file parsing without scanning)."""
        print(f"{BLUE}[INF]{RESET} Parsing DNS file: {args.parse_dns_file}")
        print(f"{BLUE}[INF]{RESET} Extracting Firebase project IDs using DNS patterns...")

        try:
            # Initialize DNS parser with firebase rules
            dns_parser = DNSParser()

            # Parse the DNS file and extract project IDs
            project_ids = dns_parser.parse_dns_file(args.parse_dns_file)

            if not project_ids:
                print(f"{YELLOW}[WARNING]{RESET} No Firebase project IDs found in the DNS file.")
                return 0

            # Print results to console
            DNSParser.print_project_ids(project_ids, args.parse_dns_file)

            # Save results to output file
            output_file = create_output_path(args.output_dir, "dns_project_ids.txt", self.run_timestamp)
            DNSParser.save_project_ids(project_ids, output_file)

            print(f"\n{BLUE}[INF]{RESET} Results saved to: {output_file}")

            return 0

        except FileNotFoundError as e:
            print(f"{RED}[ERROR]{RESET} {e}")
            return 1
        except PermissionError as e:
            print(f"{RED}[ERROR]{RESET} {e}")
            return 1
        except ValueError as e:
            print(f"{RED}[ERROR]{RESET} {e}")
            return 1
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Unexpected error parsing DNS file: {e}")
            return 1

    def _handle_extraction_mode(self, args, file_handler, process_count):
        """Handle normal extraction mode (single file or directory)."""
        if args.file:
            return self._process_single_file(args, file_handler)
        return self._process_directory(args, file_handler, process_count)

    def _process_single_file(self, args, file_handler):
        """Process a single APK file."""
        apk_path = Path(args.file)
        if not apk_path.exists():
            print(f"Error: File not found: {apk_path}")
            return 1

        if not apk_path.suffix.lower() == ".apk":
            print(f"Error: File must be an APK file: {apk_path}")
            return 1

        # Create output path in output directory
        timestamped_output = create_output_path(
            args.output_dir, "firebase_items.txt", self.run_timestamp
        )

        # Clear output file
        file_handler.clear_output_file(timestamped_output)

        if args.fast_extract:
            results = self._process_single_file_fast(
                apk_path, timestamped_output, file_handler
            )
        else:
            results = self._process_single_file_jadx(
                apk_path, timestamped_output, file_handler
            )

        if results is None:
            return 1

        return self._handle_extraction_results(
            args, file_handler, results, results, timestamped_output
        )

    def _process_single_file_fast(self, apk_path, timestamped_output, file_handler):
        """Process single file with fast extraction."""
        print(
            f"{BLUE}[INF]{RESET} Using fast extraction for {apk_path.name} - source code analysis disabled!"
        )
        print(
            f"{YELLOW}[WARNING]{RESET} Note: Firestore collections and Java patterns will not be detected!"
        )

        # Show simple progress for fast extraction
        with tqdm(total=1, desc="Scanning files", unit="file", leave=True) as pbar:
            extractor = FirebaseExtractor(apk_path.parent)
            firebase_items = extractor.process_apk(apk_path)
            pbar.update(1)

        if firebase_items:
            file_handler.save_single_result(
                apk_path.stem, firebase_items, timestamped_output
            )

        # Get results and display
        results = extractor.get_results()
        return results

    def _process_single_file_jadx(self, apk_path, timestamped_output, file_handler):
        """Process single file with JADX extraction."""
        print(
            f"{BLUE}[INF]{RESET} Processing single APK file with JADX decompilation: {apk_path.name}"
        )
        try:
            jadx_extractor = JADXExtractor(apk_path.parent, processing_mode="single")
            firebase_items = jadx_extractor.process_file_with_progress(apk_path)

            if firebase_items:
                file_handler.save_single_result(
                    apk_path.stem, firebase_items, timestamped_output
                )

            results = jadx_extractor.get_results()
            return results
        except KeyboardInterrupt:
            print(f"\n{RED}[X]{RESET} Processing interrupted by user - saving partial results...")
            # Return whatever results we have collected so far
            return jadx_extractor.get_results()

    def _process_directory(self, args, file_handler, process_count):
        """Process a directory of APK files."""
        # Process APK files
        if args.fast_extract:
            extractor = FirebaseExtractor(args.apk_dir)
            print(
                f"{BLUE}[INF]{RESET} Using fast extraction for APK processing - source code analysis disabled"
            )
            print(
                f"{YELLOW}[WARNING]{RESET} Note: Firestore collections and Java patterns will not be detected"
            )
        else:
            extractor = JADXExtractor(
                args.apk_dir, processing_mode="directory"
            )
            print(f"{BLUE}[INF]{RESET} Using JADX decompilation for APK processing...")

        # Get APK files to process
        apk_files = extractor.get_apk_files()

        if not apk_files:
            return 0

        if args.fast_extract:
            print(
                f"{BLUE}[INF]{RESET} Found {len(apk_files)} APK files to process with fast extraction using {process_count} processes..."
            )
        else:
            print(
                f"{BLUE}[INF]{RESET} Found {len(apk_files)} APK files to process with JADX using {process_count} processes (max 5 concurrent)..."
            )

        # Create output path in output directory
        timestamped_output = create_output_path(
            args.output_dir, "firebase_items.txt", self.run_timestamp
        )

        # Set extraction context for graceful shutdown
        extraction_context = {
            "args": args,
            "file_handler": file_handler,
            "timestamped_output": timestamped_output,
            "extractor": extractor
        }
        set_extraction_context(extraction_context)

        # Clear the output file at the start
        file_handler.clear_output_file(timestamped_output)

        # Process files with multiprocessing
        results = self._process_files_multiprocessing(
            args, apk_files, timestamped_output, process_count, extractor
        )

        # Handle results even if processing was interrupted
        if results is not None or is_shutdown_requested():
            # If we have results or shutdown was requested, still try to process what we have
            final_results = results if results is not None else extractor.get_results()
            if final_results:
                return self._handle_extraction_results(
                    args, file_handler, final_results, final_results, timestamped_output
                )
            print(f"\n{YELLOW}[WARNING]{RESET} No data was extracted before shutdown.")
            return 1
        # Normal case - no interruption and no results
        return 1

    def _process_files_multiprocessing(
        self, args, apk_files, timestamped_output, process_count, extractor
    ):
        """Process files using multiprocessing."""
        try:
            global_executor = ProcessPoolExecutor(max_workers=process_count)
            set_global_executor(global_executor)

            try:
                # Use position=0 to keep the main progress bar at the bottom
                with tqdm(
                    total=len(apk_files),
                    desc="Processing APKs",
                    unit="apk",
                    position=0,
                    leave=True,
                ) as pbar:
                    # Prepare arguments for multiprocessing
                    process_args = [
                        (
                            str(apk_path),
                            str(args.apk_dir),
                            args.fast_extract,
                            timestamped_output,
                        )
                        for apk_path in apk_files
                    ]

                    # Submit all tasks
                    future_to_apk = {
                        global_executor.submit(
                            process_apk_multiprocessing, args
                        ): apk_files[i]
                        for i, args in enumerate(process_args)
                    }

                    # Process completed tasks
                    for future in as_completed(future_to_apk):
                        # Check for shutdown request
                        if is_shutdown_requested():
                            print(f"\n{BLUE}[INF]{RESET} Graceful shutdown requested - cancelling remaining tasks...")
                            # Cancel all pending futures
                            for f in future_to_apk:
                                f.cancel()
                            # Break out of loop to return results collected so far
                            break

                        apk_path = future_to_apk[future]
                        try:
                            result = future.result(
                                timeout=2.0
                            )  # Add timeout to make it more responsive
                            self._handle_multiprocessing_result(result, extractor, pbar)

                        except TimeoutError:
                            # Task is taking too long, but don't fail - let it continue
                            tqdm.write(
                                f"⏳ {apk_path.name} is taking longer than expected..."
                            )
                            try:
                                result = (
                                    future.result()
                                )  # Wait without timeout for final result
                                self._handle_multiprocessing_result(
                                    result, extractor, pbar
                                )
                            except Exception as e:
                                tqdm.write(
                                    f"{RED}[X]{RESET} Final error processing {apk_path.name}: {e}"
                                )

                            pbar.update(1)
                        except Exception as e:
                            tqdm.write(
                                f"{RED}[X]{RESET} Unexpected error processing {apk_path.name}: {e}"
                            )
                            pbar.update(1)

            finally:
                cleanup_executor()

        except KeyboardInterrupt:
            print(f"\n{RED}[X]{RESET} Processing interrupted by user - saving partial results...")
            # Return whatever results we have collected so far
            return extractor.get_results()

        # Get final results
        return extractor.get_results()

    def _handle_multiprocessing_result(self, result, extractor, pbar):
        """Handle the result from multiprocessing."""
        if len(result) == 5:  # Error case with status message
            package_name, firebase_items, success, error, status_msg = result
            if not success:
                tqdm.write(f"{RED}[X]{RESET} {status_msg}")
            else:
                tqdm.write(status_msg)
        elif len(result) == 4:  # Success case with status message
            package_name, firebase_items, success, status_msg = result
            tqdm.write(status_msg)
        else:  # Legacy case
            package_name, firebase_items, success = result

        # Store results in the main extractor instance
        if firebase_items:
            extractor.results[package_name] = firebase_items

        pbar.update(1)

    def _handle_extraction_results(
        self, args, file_handler, results, final_apk_results, output_filename
    ):
        """Handle the results from extraction and perform additional operations."""
        # Results already displayed during processing - skip duplicate display
        if results:
            print(f"\n{BLUE}[INF]{RESET} Results have been saved to {output_filename}")

            # Extract and display project IDs
            print(f"\n{BLUE}[INF]{RESET} Extracting Firebase project IDs...")
            project_id_extractor = ProjectIDExtractor()
            package_project_ids = project_id_extractor.extract_project_ids_from_results(
                results
            )

            if package_project_ids:
                # Print project IDs to console
                project_id_extractor.print_project_ids(package_project_ids, results)

                # Save project IDs to file
                project_ids_output = create_output_path(
                    args.output_dir,
                    "firebase_items_project_ids.txt",
                    self.run_timestamp,
                )
                project_id_extractor.save_project_ids(
                    package_project_ids, project_ids_output
                )
                print(
                    f"\n{BLUE}[INF]{RESET} Project IDs have been saved to {project_ids_output}"
                )

                # Also save clean project IDs (just the list)
                clean_project_ids_output = create_output_path(
                    args.output_dir,
                    "firebase_items_project_ids_clean.txt",
                    self.run_timestamp,
                )
                project_id_extractor.save_clean_project_ids(
                    package_project_ids, clean_project_ids_output
                )
                print(
                    f"{BLUE}[INF]{RESET} Clean project IDs list has been saved to {clean_project_ids_output}"
                )

                # Extract and save unique collection and document names
                unique_collections, unique_documents = (
                    file_handler.extract_unique_collections_and_documents(results)
                )
                if unique_collections:
                    collections_output = create_output_path(
                        args.output_dir, "unique_collections.txt", self.run_timestamp
                    )
                    file_handler.save_unique_collections(
                        unique_collections, collections_output
                    )
                if unique_documents:
                    documents_output = create_output_path(
                        args.output_dir, "unique_documents.txt", self.run_timestamp
                    )
                    file_handler.save_unique_documents(
                        unique_documents, documents_output
                    )

                # Scan Firebase databases, storage, config, and/or firestore if scan options are enabled
                if (
                    args.scan_rtdb
                    or args.scan_storage
                    or args.scan_all
                    or args.scan_config
                    or args.scan_firestore
                    or args.write_storage
                    or args.write_firestore
                    or args.write_all
                ):
                    # Collect all unique project IDs
                    all_project_ids = set()
                    for project_ids in package_project_ids.values():
                        all_project_ids.update(project_ids)

                    if all_project_ids:
                        # Extract collection names per package
                        collections_per_package = (
                            file_handler.extract_collections_per_package(results)
                        )
                        self._perform_scanning(
                            args,
                            all_project_ids,
                            package_project_ids,
                            final_apk_results,
                            collections_per_package,
                        )
                    else:
                        print(f"{RED} No project IDs found to scan. {RESET}")
            else:
                print(f"{RED} No Firebase project IDs found. {RESET}")
        else:
            print(f"{RED}No Firebase items found.{RESET}")

        return 0

    def _perform_scanning(
        self,
        args,
        all_project_ids,
        package_project_ids,
        results,
        collections_per_package,
    ):
        """Perform Firebase scanning operations."""
        print(
            f"\n{BLUE}[INF]{RESET} Starting Firebase security scanning on {len(all_project_ids)} project ID(s)..."
        )

        # Initialize Firebase authentication if requested
        firebase_auth = None
        if getattr(args, "check_with_auth", False):
            from ..core.auth import FirebaseAuth
            firebase_auth = FirebaseAuth(timeout=10, proxy=args.proxy)
            print(f"{BLUE}[INF]{RESET} Authentication enabled - will retry 403 responses with Firebase auth")

        # Initialize scanner
        scanner = FirebaseScanner(
            rate_limit=args.scan_rate,
            fuzz_collections_wordlist=args.wordlist,
            proxy=args.proxy,
            firebase_auth=firebase_auth,
        )

        # Delegate to core scanning method (APK mode)
        return self._perform_scanning_core(
            args=args,
            scanner=scanner,
            project_ids=all_project_ids,
            package_project_ids=package_project_ids,
            results=results,
            collections_per_package=collections_per_package,
            firebase_auth=firebase_auth,
        )

    def _perform_project_id_based_scanning(self, args, scanner, project_ids_set, firebase_auth=None):
        """Perform scanning for project ID-based modes (both --project-id and --project-id-file).
        
        This method handles scanning when project IDs are provided directly via command line
        or loaded from a file, delegating to the core scanning logic.
        """
        # Delegate to core scanning method (Project ID-based modes)
        return self._perform_scanning_core(
            args=args,
            scanner=scanner,
            project_ids=project_ids_set,
            package_project_ids=None,  # Project ID-based modes - no package grouping
            results=None,
            collections_per_package=None,
            firebase_auth=firebase_auth,
        )

    def _perform_scanning_core(
        self,
        args,
        scanner,
        project_ids,
        package_project_ids=None,
        results=None,
        collections_per_package=None,
        firebase_auth=None,
    ):
        """Core scanning method that handles all scanning operations.
        
        Args:
            args: Command line arguments
            scanner: FirebaseScanner instance
            project_ids: Set of project IDs to scan
            package_project_ids: Dict of package->project_ids mapping (APK mode only)
            results: Extraction results (APK mode only)
            collections_per_package: Extracted collections (APK mode only)

        """
        # Check if manual credentials are provided
        has_manual_credentials = bool(args.app_id and args.api_key)

        # Check for write options
        write_firestore = getattr(args, "write_firestore", False) or getattr(args, "write_all", False)
        write_rtdb = getattr(args, "write_rtdb", False) or getattr(args, "write_all", False)

        # Determine what to scan based on mode
        is_apk_mode = package_project_ids is not None

        if is_apk_mode:
            # APK mode: scan based on flags or default to all
            scan_rtdb = args.scan_rtdb or args.scan_all
            scan_storage = args.scan_storage or args.scan_all
            scan_firestore = args.scan_firestore or args.scan_all
            scan_config = args.scan_config or args.scan_all
        else:
            # Project ID mode: respect specific flags or use defaults
            has_specific_scan_flags = (
                args.scan_rtdb
                or args.scan_storage
                or args.scan_firestore
                or args.scan_config
                or args.scan_all
            )
            if has_specific_scan_flags:
                # User specified specific scans, respect their choice
                scan_rtdb = args.scan_rtdb or args.scan_all
                scan_storage = args.scan_storage or args.scan_all
                scan_firestore = args.scan_firestore or args.scan_all
                # Enable config scanning only if manual credentials are provided
                scan_config = (args.scan_config or args.scan_all) and has_manual_credentials
            # No specific scan flags, default to all three (but not config unless manual credentials provided)
            elif args.write_storage or write_firestore or write_rtdb or args.write_all:
                scan_rtdb = False
                scan_storage = False
                scan_firestore = False
                scan_config = False
            else:
                scan_rtdb = True
                scan_storage = True
                scan_firestore = True
                scan_config = False  # Config scanning only available with manual credentials

        # Determine what write operations to perform
        write_storage = args.write_storage or args.write_all

        # Initialize scan results
        db_scan_results = None
        storage_scan_results = None
        config_scan_results = None
        firestore_scan_results = None

        # Initialize write results
        storage_write_results = None
        rtdb_write_results = None
        firestore_write_results = None

        # Store scan results for summary at end
        scan_summaries = []

        # Calculate how many scans are being performed for logic decisions
        scans_performed = sum(
            [scan_rtdb, scan_storage, scan_firestore, scan_config, write_storage, write_rtdb, write_firestore]
        )

        # Parse collection names for Firestore scanning
        custom_collections = None
        if args.collection_name:
            custom_collections = [name.strip() for name in args.collection_name.split(",")]

        # Setup Firebase authentication tokens if requested
        if firebase_auth and getattr(args, "check_with_auth", False):
            self._setup_firebase_auth_tokens(firebase_auth, project_ids, results, args)

        # Scan databases
        if scan_rtdb:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} Testing {BLUE}read{RESET} access to {BLUE}Firebase realtime databases{RESET} (rate: {args.scan_rate} req/s)...")
            print("=" * 80 + "\n")

            if is_apk_mode:
                db_output_file = create_output_path(
                    args.output_dir, "read_output_db.txt", self.run_timestamp
                )
                db_scan_results = scanner.scan_databases(
                    project_ids, package_project_ids, db_output_file
                )
            else:
                db_output_file = (
                    create_output_path(
                        args.output_dir, "read_output_db.txt", self.run_timestamp
                    )
                    if scans_performed > 1
                    else create_output_path(
                        args.output_dir, "full_scan_output.txt", self.run_timestamp
                    )
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                db_scan_results = scanner.scan_databases(
                    project_ids,
                    output_file=db_output_file,
                    create_open_only=create_open_only,
                )

            print(
                f"{BLUE}[INF]{RESET} Database scan results have been saved to {db_output_file}"
            )

            if scans_performed > 1:
                # Multiple scans: print details immediately, save summary for end
                scanner.print_scan_details(
                    db_scan_results, "DATABASES", package_project_ids
                )
                scan_summaries.append((db_scan_results, "DATABASES"))
            else:
                # Single scan: print everything immediately
                scanner.print_scan_results(
                    db_scan_results, "DATABASES", package_project_ids
                )

        # Scan storage
        if scan_storage:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} Testing {BLUE}read{RESET} access to {BLUE}Firebase storage buckets{RESET} (rate: {args.scan_rate} req/s)...")
            print("=" * 80 + "\n")

            if is_apk_mode:
                storage_output_file = create_output_path(
                    args.output_dir, "read_output_storage.txt", self.run_timestamp
                )
                storage_scan_results = scanner.scan_storage_buckets(
                    project_ids, package_project_ids, storage_output_file
                )
            else:
                storage_output_file = (
                    create_output_path(
                        args.output_dir, "read_output_storage.txt", self.run_timestamp
                    )
                    if scans_performed > 1
                    else create_output_path(
                        args.output_dir, "full_scan_output.txt", self.run_timestamp
                    )
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                storage_scan_results = scanner.scan_storage_buckets(
                    project_ids,
                    output_file=storage_output_file,
                    create_open_only=create_open_only,
                )

            print(
                f"{BLUE}[INF]{RESET} Storage scan results have been saved to {storage_output_file}"
            )

            if scans_performed > 1:
                # Multiple scans: print details immediately, save summary for end
                scanner.print_scan_details(
                    storage_scan_results, "STORAGE", package_project_ids
                )
                # Note: authenticated results are cleared within print_scan_details after display
                scan_summaries.append((storage_scan_results, "STORAGE"))
            else:
                # Single scan: print everything immediately
                scanner.print_scan_results(
                    storage_scan_results, "STORAGE", package_project_ids
                )
                # Note: authenticated results are cleared within print_scan_results after display

        # Scan Remote Config
        if scan_config:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} Testing {BLUE}read{RESET} access to {BLUE}Firebase Remote Config{RESET} (rate: {args.scan_rate} req/s)...")
            print("=" * 80 + "\n")

            if is_apk_mode:
                config_data = extract_config_data(results)
                if config_data:
                    config_output_file = create_output_path(
                        args.output_dir, "read_output_config.txt", self.run_timestamp
                    )
                    config_scan_results = scanner.scan_config(
                        config_data, package_project_ids, config_output_file
                    )
                    print(
                        f"{BLUE}[INF]{RESET} Remote Config scan results have been saved to {config_output_file}"
                    )

                    if scans_performed > 1:
                        # Multiple scans: print details immediately, save summary for end
                        scanner.print_scan_details(
                            config_scan_results, "REMOTE CONFIG", package_project_ids
                        )
                        scan_summaries.append((config_scan_results, "REMOTE CONFIG"))
                    else:
                        # Single scan: print everything immediately
                        scanner.print_scan_results(
                            config_scan_results, "REMOTE CONFIG", package_project_ids
                        )
                else:
                    print(
                        "No Firebase Remote Config data (API keys and App IDs) found in results."
                    )
            else:
                # Project ID mode - config scanning requires manual credentials
                config_output_file = create_output_path(
                    args.output_dir, "read_output_config.txt", self.run_timestamp
                )
                # Build config_data dictionary for project ID mode
                config_data = {}
                for project_id in project_ids:
                    config_data[project_id] = {
                        "api_key": args.api_key,
                        "app_id": args.app_id,
                        "cert_sha1": args.cert_sha1,
                        "package_name": args.package_name
                    }

                config_scan_results = scanner.scan_config(
                    config_data, package_project_ids=None, output_file=config_output_file
                )
                print(
                    f"{BLUE}[INF]{RESET} Remote Config scan results have been saved to {config_output_file}"
                )

                if scans_performed > 1:
                    # Multiple scans: print details immediately, save summary for end
                    scanner.print_scan_details(config_scan_results, "REMOTE CONFIG")
                    scan_summaries.append((config_scan_results, "REMOTE CONFIG"))
                else:
                    # Single scan: print everything immediately
                    scanner.print_scan_results(config_scan_results, "REMOTE CONFIG")

        # Scan Firestore
        if scan_firestore:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} Testing {BLUE}read{RESET} access to {BLUE}Firestore databases{RESET} (rate: {args.scan_rate} req/s)...")
            print("=" * 80 + "\n")

            if is_apk_mode:
                firestore_output_file = create_output_path(
                    args.output_dir, "read_output_firestore.txt", self.run_timestamp
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                firestore_scan_results = scanner.scan_firestore(
                    project_ids,
                    collections_per_package,
                    package_project_ids,
                    firestore_output_file,
                    create_open_only,
                    custom_collections,
                )
            else:
                firestore_output_file = (
                    create_output_path(
                        args.output_dir, "read_output_firestore.txt", self.run_timestamp
                    )
                    if scans_performed > 1
                    else create_output_path(
                        args.output_dir, "full_scan_output.txt", self.run_timestamp
                    )
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                firestore_scan_results = scanner.scan_firestore(
                    project_ids,
                    output_file=firestore_output_file,
                    create_open_only=create_open_only,
                    custom_collections=custom_collections,
                )

            print(
                f"{BLUE}[INF]{RESET} Firestore scan results have been saved to {firestore_output_file}"
            )

            if scans_performed > 1:
                # Multiple scans: print details immediately, save summary for end
                scanner.print_scan_details(
                    firestore_scan_results, "FIRESTORE", package_project_ids
                )
                scan_summaries.append((firestore_scan_results, "FIRESTORE"))
            else:
                # Single scan: print everything immediately
                scanner.print_scan_results(
                    firestore_scan_results, "FIRESTORE", package_project_ids
                )

        # Test write access to storage
        if write_storage:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} Testing {BLUE}write{RESET} access to {BLUE}Firebase storage buckets{RESET} (rate: {args.scan_rate} req/s)...")
            print("=" * 80 + "\n")

            if is_apk_mode:
                storage_write_output_file = create_output_path(
                    args.output_dir, "write_output_storage.txt", self.run_timestamp
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                storage_write_results = scanner.write_to_storage_buckets(
                    project_ids,
                    args.write_storage_file,
                    package_project_ids,
                    storage_write_output_file,
                    create_open_only,
                )
            else:
                storage_write_output_file = (
                    create_output_path(
                        args.output_dir, "write_output_storage.txt", self.run_timestamp
                    )
                    if scans_performed > 1
                    else create_output_path(
                        args.output_dir, "full_scan_output.txt", self.run_timestamp
                    )
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                storage_write_results = scanner.write_to_storage_buckets(
                    project_ids,
                    args.write_storage_file,
                    output_file=storage_write_output_file,
                    create_open_only=create_open_only,
                )

            print(
                f"{BLUE}[INF]{RESET} Storage write results have been saved to {storage_write_output_file}"
            )

            if scans_performed > 1:
                # Multiple scans: print details immediately, save summary for end
                scanner.print_scan_details(
                    storage_write_results, "STORAGE WRITE", package_project_ids
                )
                scan_summaries.append((storage_write_results, "STORAGE WRITE"))
            else:
                # Single scan: print everything immediately
                scanner.print_scan_results(
                    storage_write_results, "STORAGE WRITE", package_project_ids
                )

        # Test write access to Realtime Database
        if write_rtdb:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} Testing {BLUE}write{RESET} access to {BLUE}Firebase Realtime Database{RESET} (rate: {args.scan_rate} req/s)...")
            print("=" * 80 + "\n")

            if is_apk_mode:
                rtdb_write_output_file = create_output_path(
                    args.output_dir, "write_output_rtdb.txt", self.run_timestamp
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                rtdb_write_results = scanner.write_to_databases(
                    project_ids,
                    args.write_rtdb_file,
                    package_project_ids,
                    rtdb_write_output_file,
                    create_open_only,
                )
            else:
                rtdb_write_output_file = (
                    create_output_path(
                        args.output_dir, "write_output_rtdb.txt", self.run_timestamp
                    )
                    if scans_performed > 1
                    else create_output_path(
                        args.output_dir, "full_scan_output.txt", self.run_timestamp
                    )
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                rtdb_write_results = scanner.write_to_databases(
                    project_ids,
                    args.write_rtdb_file,
                    output_file=rtdb_write_output_file,
                    create_open_only=create_open_only,
                )

            print(
                f"{BLUE}[INF]{RESET} RTDB write results have been saved to {rtdb_write_output_file}"
            )

            if scans_performed > 1:
                # Multiple scans: print details immediately, save summary for end
                scanner.print_scan_details(
                    rtdb_write_results, "REALTIME DATABASE WRITE", package_project_ids
                )
                scan_summaries.append((rtdb_write_results, "REALTIME DATABASE WRITE"))
            else:
                # Single scan: print everything immediately
                scanner.print_scan_results(
                    rtdb_write_results, "REALTIME DATABASE WRITE", package_project_ids
                )

        # Test write access to Firestore
        if write_firestore:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} Testing {BLUE}write{RESET} access to {BLUE}Firestore databases{RESET} (rate: {args.scan_rate} req/s)...")
            print("=" * 80 + "\n")

            if is_apk_mode:
                firestore_write_output_file = create_output_path(
                    args.output_dir, "write_output_firestore.txt", self.run_timestamp
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                firestore_write_results = scanner.write_to_firestore_databases(
                    project_ids,
                    args.write_firestore_value,
                    package_project_ids,
                    firestore_write_output_file,
                    create_open_only,
                )
            else:
                firestore_write_output_file = (
                    create_output_path(
                        args.output_dir, "write_output_firestore.txt", self.run_timestamp
                    )
                    if scans_performed > 1
                    else create_output_path(
                        args.output_dir, "full_scan_output.txt", self.run_timestamp
                    )
                )
                # Don't create open-only files for individual scans if doing combined scan
                # Exception: Always create open-only files when authentication is enabled
                create_open_only = not (scans_performed > 1) or (firebase_auth and getattr(args, "check_with_auth", False))
                firestore_write_results = scanner.write_to_firestore_databases(
                    project_ids,
                    args.write_firestore_value,
                    output_file=firestore_write_output_file,
                    create_open_only=create_open_only,
                )

            print(
                f"{BLUE}[INF]{RESET} Firestore write results have been saved to {firestore_write_output_file}"
            )

            if scans_performed > 1:
                # Multiple scans: print details immediately, save summary for end
                scanner.print_scan_details(
                    firestore_write_results, "FIRESTORE WRITE", package_project_ids
                )
                scan_summaries.append((firestore_write_results, "FIRESTORE WRITE"))
            else:
                # Single scan: print everything immediately
                scanner.print_scan_results(
                    firestore_write_results, "FIRESTORE WRITE", package_project_ids
                )

        # Save combined results if multiple scan types were performed
        warning_messages = []
        combined_output_file = None
        if scans_performed > 1:
            if is_apk_mode:
                filename = "read_output_full.txt" if args.scan_all or args.write_all else "full_scan_output.txt"
                combined_output_file = create_output_path(
                    args.output_dir, filename, self.run_timestamp
                )
                # For --read-all: collect warning messages to print at end, for others: print immediately
                print_warnings_immediately = not args.scan_all and not args.write_all
                warning_messages = scanner.save_combined_scan_results(
                    db_scan_results=db_scan_results,
                    storage_scan_results=storage_scan_results,
                    config_scan_results=config_scan_results,
                    firestore_scan_results=firestore_scan_results,
                    storage_write_results=storage_write_results,
                    rtdb_write_results=rtdb_write_results,
                    firestore_write_results=firestore_write_results,
                    output_file=combined_output_file,
                    package_project_ids=package_project_ids,
                    print_warnings=print_warnings_immediately,
                )
                # For --read-all: defer this message, for others: print immediately
                if not args.scan_all and not args.write_all:
                    print(
                        f"\n{BLUE}[INF]{RESET} Combined scan results have been saved to {combined_output_file}"
                    )
            else:
                combined_output_file = create_output_path(
                    args.output_dir, "full_scan_output.txt", self.run_timestamp
                )
                # Defer warning messages to print at end with summaries
                warning_messages = scanner.save_combined_scan_results(
                    db_scan_results=db_scan_results,
                    storage_scan_results=storage_scan_results,
                    config_scan_results=config_scan_results,
                    firestore_scan_results=firestore_scan_results,
                    storage_write_results=storage_write_results,
                    rtdb_write_results=rtdb_write_results,
                    firestore_write_results=firestore_write_results,
                    output_file=combined_output_file,
                    package_project_ids=None,
                    print_warnings=False,
                )

                # Add authentication summary to combined file if authentication was used
                if firebase_auth and getattr(args, "check_with_auth", False):
                    self._save_auth_results_summary_to_file(scanner, firebase_auth, combined_output_file)

        # Print all summaries at the end when multiple scans are performed
        if scans_performed > 1 and scan_summaries:
            print("\n" + "=" * 80)
            print(f"{BLUE}[INF]{RESET} SCAN SUMMARIES")
            print("=" * 80)
            for scan_results, scan_type in scan_summaries:
                scanner.print_scan_summary(scan_results, scan_type, args.output_dir)

            # Print collected warning messages at the end (APK mode with --read-all/--write-all or Project ID modes)
            if (is_apk_mode and (args.scan_all or args.write_all) and warning_messages) or (not is_apk_mode and warning_messages):
                print("\n" + "=" * 80)
                for warning in warning_messages:
                    print(warning)

        # Display authentication results summary if authentication was used
        if firebase_auth and getattr(args, "check_with_auth", False):
            self._display_auth_results_summary(scanner, firebase_auth)

        # Print combined results save message at the very end (after authentication summary)
        if scans_performed > 1:
            if (is_apk_mode and (args.scan_all or args.write_all) and combined_output_file) or (not is_apk_mode and combined_output_file):
                print(
                    f"\n{BLUE}[INF]{RESET} Combined scan results have been saved to {combined_output_file}"
                )

        return 0

    def _generate_auth_results_summary(self, scanner, firebase_auth):
        """Generate authentication results summary as a list of strings."""
        lines = []

        # Get authentication summary from firebase_auth
        auth_summary = firebase_auth.get_auth_summary()

        # Get authentication success summary from scanner
        auth_success_summary = scanner.get_auth_success_summary()

        # Get authenticated results to check which collections actually have data
        authenticated_results = scanner.get_authenticated_results()

        # Count total successful authenticated URLs
        total_auth_success_urls = sum(len(urls) for urls in auth_success_summary.values())

        lines.append(f"Firebase account creation attempts: {auth_summary['total_projects']}")
        lines.append(f"  Successful authentications: {auth_summary['successful_auths']}")
        lines.append(f"  Failed authentications: {auth_summary['failed_auths']}\n")

        if total_auth_success_urls > 0:
            # Count projects that had any authenticated resources
            auth_projects = set()
            projects_with_db = set()
            projects_with_storage = set()
            projects_with_firestore = set()
            firestore_collection_count = 0

            for _, urls in auth_success_summary.items():
                if urls:
                    for url in urls:
                        # Extract project ID from URL to count unique projects
                        if "firestore.googleapis.com" in url:
                            project_match = url.split("projects/")[1].split("/")[0] if "projects/" in url else None
                            if project_match:
                                auth_projects.add(project_match)
                                projects_with_firestore.add(project_match)  # Any accessible collection means database access

                                # Only count collections that actually have data
                                for proj_id, proj_results in authenticated_results.items():
                                    if url in proj_results and proj_results[url].get("has_data", True):
                                        firestore_collection_count += 1
                                        break
                        elif "firebaseio.com" in url or "firebasedatabase.app" in url:
                            project_match = url.split("//")[1].split("-")[0] if "//" in url else None
                            if project_match:
                                auth_projects.add(project_match)
                                projects_with_db.add(project_match)
                        elif "firebasestorage.googleapis.com" in url:
                            # Extract project ID from Firebase Storage URLs
                            # Pattern: https://firebasestorage.googleapis.com/v0/b/PROJECT-ID.appspot.com/o
                            # Pattern: https://firebasestorage.googleapis.com/v0/b/PROJECT-ID.firebasestorage.app/o
                            import re
                            project_match = None
                            appspot_match = re.search(r"/b/([^/]+)\.appspot\.com/", url)
                            if appspot_match:
                                project_match = appspot_match.group(1)
                            else:
                                firebasestorage_match = re.search(r"/b/([^/]+)\.firebasestorage\.app/", url)
                                if firebasestorage_match:
                                    project_match = firebasestorage_match.group(1)

                            if project_match:
                                auth_projects.add(project_match)
                                projects_with_storage.add(project_match)


            if len(projects_with_db) > 0:
                lines.append(f"Total projects with Realtime Database accessible with authentication: {len(projects_with_db)}")
            if len(projects_with_storage) > 0:
                lines.append(f"Total projects with Storage buckets accessible with authentication: {len(projects_with_storage)}")
            if len(projects_with_firestore) > 0:
                lines.append(f"Total projects with Firestore databases accessible with authentication: {len(projects_with_firestore)}")
            if firestore_collection_count > 0:
                lines.append(f"Total authenticated Firestore collections found: {firestore_collection_count}")

            lines.append(f"\n{YELLOW}[!]{RESET} Found {total_auth_success_urls} resource(s) that were protected but accessible with authentication!")
        else:
            lines.append("\nNo accessable resources found with authenticated scanning (all were already accessible without authentication or completely restricted)")

        return lines

    def _display_auth_results_summary(self, scanner, firebase_auth):
        """Display authentication results summary to console."""
        print("\n" + "=" * 80)
        print(f"{GREEN}[AUTH]{RESET} {ORANGE}AUTHENTICATION SCAN SUMMARY{RESET}")
        print("=" * 80)

        summary_lines = self._generate_auth_results_summary(scanner, firebase_auth)
        for line in summary_lines:
            print(line)

        print("=" * 80)

    def _save_auth_results_summary_to_file(self, scanner, firebase_auth, output_file):
        """Save authentication results summary to file."""
        with open(output_file, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write("[AUTH] AUTHENTICATION SCAN SUMMARY\n")
            f.write("=" * 80 + "\n")

            summary_lines = self._generate_auth_results_summary(scanner, firebase_auth)
            for line in summary_lines:
                f.write(line + "\n")

            f.write("=" * 80 + "\n")

    def _setup_firebase_auth_tokens(self, firebase_auth, project_ids, results, args):
        """Setup Firebase authentication tokens for projects with enhanced key selection.
        
        Uses google_api_key for Firebase_Project_ID and Other_Google_API_Key for other projects.
        Validates JWT aud field against package project IDs.
        
        Args:
            firebase_auth: FirebaseAuth instance
            project_ids: Set of project IDs to authenticate
            results: Extraction results (None for project ID mode)
            args: Command line arguments

        """
        # Skip authentication setup if using --resume-auth-file mode
        # (authentication is already handled in _handle_resume_auth_file_mode)
        if getattr(args, "resume_auth_file", None):
            return

        # Check if we have extraction results (APK mode) or manual API key (project ID mode)
        auth_data = {}
        all_expected_project_ids = list(project_ids)

        if results:
            # APK mode: Extract enhanced auth data from results
            auth_data = extract_enhanced_auth_data(results)
            print(f"{BLUE}[AUTH]{RESET} Extracted authentication data for {len(auth_data)} project(s)")
        # Project ID mode: Use manual API key if provided
        elif getattr(args, "api_key", None):
            for project_id in project_ids:
                cert_sha1 = getattr(args, "cert_sha1", None)
                auth_data[project_id] = {
                    "main_project_id": project_id,
                    "api_keys": [args.api_key],
                    "app_id": getattr(args, "app_id", None),
                    "cert_sha1_list": [cert_sha1] if cert_sha1 else [],
                    "package_name": getattr(args, "package_name", project_id)
                }

        # Attempt to create authentication tokens with JWT validation
        successful_auths = 0
        failed_auths = 0
        validated_projects = {}  # Maps auth_project_id -> validated_project_id

        for project_id in project_ids:
            project_auth_data = auth_data.get(project_id)
            if not project_auth_data or not project_auth_data.get("api_keys"):
                print(f"{YELLOW}[AUTH]{RESET} No API keys available for project {project_id}, skipping authentication")
                failed_auths += 1
                continue

            api_keys = project_auth_data["api_keys"]
            print(f"{BLUE}[AUTH]{RESET} Attempting authentication for project {project_id} with {len(api_keys)} API key(s)...")

            # Try authentication with multiple keys and JWT validation
            package_name = project_auth_data.get("package_name")
            cert_sha1_list = project_auth_data.get("cert_sha1_list", [])
            app_id = project_auth_data.get("app_id")  # Will be None for auth-only extraction

            # Create timestamped output directory (same as scanning outputs)
            timestamped_output_path = create_output_path(args.output_dir, "dummy.txt", self.run_timestamp)
            timestamped_output_dir = Path(timestamped_output_path).parent

            result = firebase_auth.create_account_with_multiple_keys(
                project_id, api_keys, args.email, args.password, all_expected_project_ids, package_name, cert_sha1_list, app_id, str(timestamped_output_dir)
            )

            if result:
                token, validated_project_id = result
                successful_auths += 1
                validated_projects[project_id] = validated_project_id
                print(f"{GREEN}[AUTH]{RESET} Successfully authenticated and validated project {validated_project_id}")
            else:
                failed_auths += 1

            # Rate limiting - sleep between authentication requests to respect API limits
            time.sleep(1.0 / args.scan_rate)

        print(f"{BLUE}[AUTH]{RESET} Authentication setup complete: {successful_auths} successful, {failed_auths} failed/skipped")

        if successful_auths == 0 and not results and not getattr(args, "api_key", None):
            print(f"{YELLOW}[WARNING]{RESET} No API key provided via --api-key. Authentication will be skipped.")
            print("   Use --api-key with your Firebase API key to enable authentication for project ID scanning.")


