"""Base Scanner for OpenFirebase

Contains shared functionality for all Firebase scanners.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set

import requests
import urllib3

from ..core.config import (
    BLUE,
    DEFAULT_RATE_LIMIT,
    DEFAULT_TIMEOUT,
    GOLD,
    GREEN,
    GREY,
    LIME,
    ORANGE,
    RED,
    RESET,
    RESPONSE_CONTENT_MAX_LENGTH,
    STATUS_BAD_REQUEST,
    STATUS_FORBIDDEN,
    STATUS_LOCKED,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_PRECONDITION_FAILED,
    STATUS_TOO_MANY_REQUESTS,
    STATUS_UNAUTHORIZED,
    YELLOW,
)


class BaseScanner(ABC):
    """Abstract base class for all Firebase scanners."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        fuzz_collections_wordlist: str = None,
        proxy: str = None,
        firebase_auth=None,
    ):
        """Initialize the scanner with request timeout and rate limiting.

        Args:
            timeout: Request timeout in seconds
            rate_limit: Requests per second (default: 1.0)
            fuzz_collections_wordlist: Path to wordlist file for collection fuzzing (enables fuzzing if provided)
            proxy: Proxy URL for HTTP requests (format: protocol://host:port)
            firebase_auth: FirebaseAuth instance for authenticated requests

        """
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.fuzz_collections = bool(fuzz_collections_wordlist)
        self.wordlist_path = fuzz_collections_wordlist
        self.firebase_auth = firebase_auth
        self.session = requests.Session()
        # Set a user agent to avoid being blocked
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        # Track authentication results
        self.auth_success_urls: Set[str] = set()  # URLs that failed unauth but succeeded with auth
        self.authenticated_results: Dict[str, Dict[str, str]] = {}  # Store authenticated results for display
        self.all_authenticated_results: Dict[str, Dict[str, Dict[str, str]]] = {}  # Store all authenticated results by project_id

        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
            # Disable SSL verification for intercepting proxies like Burp Suite
            self.session.verify = False
            # Suppress SSL warnings to avoid cluttering output
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Load wordlist if fuzzing is enabled
        self.wordlist = []
        if self.fuzz_collections:
            self._load_wordlist()

    def _load_wordlist(self):
        """Load collection names from wordlist file."""
        from ..utils import load_wordlist

        self.wordlist, success = load_wordlist(self.wordlist_path)
        if not success:
            self.fuzz_collections = False

    def _truncate_response_content(self, text: str) -> str:
        """Truncate response content to a reasonable length.

        Args:
            text: The response text to truncate

        Returns:
            Truncated text with ellipsis if needed

        """
        if len(text) > RESPONSE_CONTENT_MAX_LENGTH:
            return text[:RESPONSE_CONTENT_MAX_LENGTH] + "..."
        return text

    def _build_response_dict(
        self,
        status_code: int,
        message: str,
        accessible: bool,
        security: str,
        response_text: str = "",
        **kwargs,
    ) -> Dict[str, str]:
        """Build a standardized response dictionary.

        Args:
            status_code: HTTP status code
            message: Human-readable message
            accessible: Whether the resource is accessible
            security: Security classification
            response_text: Response content from the server
            **kwargs: Additional fields to include

        Returns:
            Standardized response dictionary

        """
        result = {
            "status": str(status_code),
            "message": message,
            "accessible": accessible,
            "security": security,
        }

        if response_text:
            result["response_content"] = self._truncate_response_content(response_text)

        result.update(kwargs)
        return result

    def _handle_common_status_codes(self, response) -> Dict[str, str]:
        """Handle common HTTP status codes that are the same for all scanners.

        Args:
            response: HTTP response object

        Returns:
            Response dictionary or None if status code is not handled here

        """
        if response.status_code == 200:
            return self._build_response_dict(
                200, "Public access", True, "PUBLIC", response.text
            )
        if response.status_code == 401:
            return self._build_response_dict(
                401, "Unauthorized", False, "PROTECTED", response.text
            )
        if response.status_code == 403:
            return self._build_response_dict(
                403, "Permission denied", False, "PROTECTED", response.text
            )
        if response.status_code == 429:
            return self._build_response_dict(
                429,
                "Rate limited - too many requests",
                False,
                "RATE_LIMITED",
                response.text,
            )

        return None

    def _handle_common_status_codes_with_auth(
        self,
        response,
        url: str,
        method: str = "GET",
        **request_kwargs
    ) -> Dict[str, str]:
        """Handle common HTTP status codes with authentication retry support.

        Args:
            response: Initial HTTP response object
            url: URL that was requested
            method: HTTP method used
            **request_kwargs: Original request arguments

        Returns:
            Response dictionary for the original request (auth retries stored separately)

        """
        # If we got a 401 (Unauthorized) or 403 (Forbidden) and have Firebase auth, try authenticated request
        if response.status_code in [401, 403] and self.firebase_auth:
            project_id = self._extract_project_id_from_url(url)
            if project_id:
                # Try to get or create auth token for this project
                auth_response = self._try_authenticated_request(
                    url, method, timeout=self.timeout, **request_kwargs
                )
                # Note: _try_authenticated_request now stores the auth result internally
                # We always continue to show the original result, auth results shown separately

        # Handle standard responses
        if response.status_code == 200:
            return self._build_response_dict(
                200, "Public access", True, "PUBLIC", response.text
            )
        if response.status_code == 401:
            return self._build_response_dict(
                401, "Unauthorized", False, "PROTECTED", response.text
            )
        if response.status_code == 403:
            return self._build_response_dict(
                403, "Permission denied", False, "PROTECTED", response.text
            )
        if response.status_code == 429:
            return self._build_response_dict(
                429,
                "Rate limited - too many requests",
                False,
                "RATE_LIMITED",
                response.text,
            )

        return None

    def _extract_project_id_from_url(self, url: str) -> Optional[str]:
        """Extract Firebase project ID from a URL.
        
        Args:
            url: Firebase URL
            
        Returns:
            Project ID if found, None otherwise

        """
        import re

        # Firebase Realtime Database patterns
        rtdb_match = re.search(r"https://([^.]+)\.firebaseio\.com", url)
        if rtdb_match:
            project_id = rtdb_match.group(1)
            # Remove -default-rtdb suffix if present
            if project_id.endswith("-default-rtdb"):
                project_id = project_id[:-len("-default-rtdb")]
            return project_id

        # Firebase region redirect patterns
        # Handle URLs like https://project-id.region.firebasedatabase.app
        rtdb_region_match = re.search(r"https://([^.]+)\.([^.]+)\.firebasedatabase\.app", url)
        if rtdb_region_match:
            project_id = rtdb_region_match.group(1)
            # Remove -default-rtdb suffix if present
            if project_id.endswith("-default-rtdb"):
                project_id = project_id[:-len("-default-rtdb")]
            return project_id

        # Firestore patterns
        firestore_match = re.search(r"/projects/([^/]+)/", url)
        if firestore_match:
            return firestore_match.group(1)

        # Firebase Storage patterns
        storage_match = re.search(r"/b/([^/]+)\.appspot\.com/", url)
        if storage_match:
            return storage_match.group(1)

        # Firebase Storage (.firebasestorage.app) patterns
        storage_app_match = re.search(r"/b/([^/]+)\.firebasestorage\.app/", url)
        if storage_app_match:
            return storage_app_match.group(1)

        return None

    def _is_realtime_database(self, url: str) -> bool:
        """Check if URL is for Firebase Realtime Database.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is for Realtime Database, False otherwise

        """
        return (".firebaseio.com" in url or
                ".firebasedatabase.app" in url)

    def _try_authenticated_request(
        self,
        url: str,
        method: str = "GET",
        **kwargs
    ) -> Optional[requests.Response]:
        """Try to make an authenticated request if Firebase auth is available.
        
        Args:
            url: URL to request
            method: HTTP method ('GET', 'POST', etc.)
            **kwargs: Additional arguments for the request
            
        Returns:
            Response object if successful, None if auth not available or failed

        """
        if not self.firebase_auth:
            return None

        project_id = self._extract_project_id_from_url(url)
        if not project_id:
            return None

        auth_token = self.firebase_auth.get_auth_token(project_id)
        if not auth_token:
            return None

        # Determine authentication method based on service type
        if self._is_realtime_database(url):
            # Realtime Database uses query parameter ?auth=<token>
            separator = "&" if "?" in url else "?"
            authenticated_url = f"{url}{separator}auth={auth_token}"
            # Keep headers as-is for RTDB
        else:
            # Firestore and Storage use Authorization header
            authenticated_url = url
            # Make a copy of headers to avoid modifying the original
            auth_headers = kwargs.get("headers", {}).copy()
            auth_headers["Authorization"] = f"Bearer {auth_token}"
            kwargs["headers"] = auth_headers

        try:
            if method.upper() == "GET":
                response = self.session.get(authenticated_url, **kwargs)
            elif method.upper() == "POST":
                response = self.session.post(authenticated_url, **kwargs)
            elif method.upper() == "PUT":
                response = self.session.put(authenticated_url, **kwargs)
            elif method.upper() == "DELETE":
                response = self.session.delete(authenticated_url, **kwargs)
            else:
                return None

            # Store authenticated result for later display (don't print immediately)
            auth_result = {}

            # Determine response message based on status code
            if response.status_code == 200:
                auth_result["message"] = "Public access (authenticated)"
                auth_result["security"] = "PUBLIC_AUTH"

                # For Firestore, track auth success more carefully
                should_track = True
                if "firestore.googleapis.com" in url:
                    try:
                        import json
                        response_json = response.json() if response.text else {}
                        if response_json == {} or response_json.get("documents") == []:
                            # Empty Firestore collection - always track as auth success since database is accessible
                            # This represents a security finding (database accessible with auth) even if collection is empty
                            should_track = True
                            auth_result["has_data"] = False
                        else:
                            auth_result["has_data"] = True
                    except (ValueError, json.JSONDecodeError):
                        # Can't parse JSON, assume it has content
                        auth_result["has_data"] = True

                if should_track:
                    self.auth_success_urls.add(url)
            elif response.status_code == 401:
                auth_result["message"] = "Unauthorized (even with auth)"
                auth_result["security"] = "PROTECTED"
            elif response.status_code == 403:
                auth_result["message"] = "Permission denied (even with auth)"
                auth_result["security"] = "PROTECTED"
            elif response.status_code == 404:
                auth_result["message"] = "Resource not found"
                auth_result["security"] = "NOT_FOUND"
            else:
                auth_result["message"] = f"HTTP {response.status_code}"
                auth_result["security"] = "UNKNOWN"

            auth_result["status"] = str(response.status_code)
            # Store response content, truncating if too long
            if response.text is not None:
                auth_result["response_content"] = self._truncate_response_content(response.text)
            else:
                auth_result["response_content"] = ""

            # Store for later display
            self.authenticated_results[url] = auth_result

            return response

        except requests.exceptions.RequestException:
            return None

    def get_auth_success_urls(self) -> Set[str]:
        """Get URLs that failed unauthenticated but succeeded with authentication.
        
        Returns:
            Set of URLs that required authentication

        """
        return self.auth_success_urls.copy()

    def clear_all_authenticated_results(self):
        """Clear all stored authenticated results."""
        self.all_authenticated_results.clear()
        self.authenticated_results.clear()
        self.auth_success_urls.clear()

    def _display_and_clear_authenticated_results(self, scan_results, scan_type="DATABASES"):
        """Display authenticated results in separate section with proper header and clear them."""
        if not self.all_authenticated_results:
            return

        # Check if there are any authenticated results for URLs that were tested
        has_relevant_auth_results = False
        for project_id, auth_results in self.all_authenticated_results.items():
            for url, auth_result in auth_results.items():
                # Only show authenticated results for URLs that were tested in scan_results
                for proj_results in scan_results.values():
                    if url in proj_results:
                        has_relevant_auth_results = True
                        break
                if has_relevant_auth_results:
                    break
            if has_relevant_auth_results:
                break

        if not has_relevant_auth_results:
            return

        # Map scan types to display names for authenticated results
        auth_type_mapping = {
            "DATABASES": "FIREBASE REALTIME DATABASE READ RESULTS",
            "DATABASE WRITE": "FIREBASE REALTIME DATABASE WRITE RESULTS",
            "STORAGE": "FIREBASE STORAGE READ RESULTS",
            "STORAGE WRITE": "FIREBASE STORAGE WRITE RESULTS",
            "CONFIG": "FIREBASE REMOTE CONFIG READ RESULTS",
            "FIRESTORE": "FIREBASE FIRESTORE READ RESULTS",
            "FIRESTORE WRITE": "FIREBASE FIRESTORE WRITE RESULTS"
        }

        base_display_name = auth_type_mapping.get(scan_type, f"FIREBASE {scan_type} RESULTS")
        auth_display_name = f"{GREEN}[AUTH]{RESET} {ORANGE}{base_display_name}{RESET}"
        print("\n" + "=" * 80)
        print(auth_display_name)
        print("=" * 80)

        # Group authenticated results by project ID
        for project_id, auth_results in self.all_authenticated_results.items():
            project_has_results = False
            # First check if this project has any relevant results
            for url, auth_result in auth_results.items():
                found_in_results = False
                for proj_results in scan_results.values():
                    if url in proj_results:
                        found_in_results = True
                        break
                if found_in_results:
                    project_has_results = True
                    break

            if not project_has_results:
                continue

            print(f"\n{ORANGE}Project ID: {project_id}{RESET}")
            print("-" * 50)

            for url, auth_result in auth_results.items():
                # Only show authenticated results for URLs that were tested in scan_results
                found_in_results = False
                for proj_results in scan_results.values():
                    if url in proj_results:
                        found_in_results = True
                        break

                if found_in_results:
                    status = auth_result.get("status", "unknown")
                    security = auth_result.get("security", "unknown")
                    message = auth_result.get("message", "No message")

                    # Display authenticated results in the same format as regular results
                    if status == "200":
                        if "storage" in url.lower():
                            print(f"  {LIME}[+]{RESET} PUBLIC STORAGE: {url}")
                            print(f"     Status: {status} - Storage is publicly accessible for any authenticated user")
                        elif "firestore" in url.lower():
                            # Check if Firestore collection has content
                            response_content = auth_result.get("response_content", "")
                            try:
                                import json
                                content_json = json.loads(response_content) if response_content else {}
                                if content_json == {} or content_json.get("documents") == []:
                                    # Empty collection - show database accessible but collection doesn't exist
                                    print(f"  {YELLOW}[!]{RESET}  PUBLIC FIRESTORE DATABASE: {url}")
                                    print(f"     Status: {status} - Database is publicly accessible with authentication")
                                else:
                                    # Collection has content
                                    print(f"  {LIME}[+]{RESET} PUBLIC FIRESTORE: {url}")
                                    print(f"     Status: {status} - Firestore is publicly accessible for any authenticated user")
                            except (json.JSONDecodeError, ValueError):
                                # If we can't parse JSON, fall back to generic message
                                print(f"  {LIME}[+]{RESET} PUBLIC FIRESTORE: {url}")
                                print(f"     Status: {status} - Firestore is publicly accessible for any authenticated user")
                        elif "firebaseremoteconfig" in url.lower():
                            print(f"  {LIME}[+]{RESET} PUBLIC REMOTE CONFIG: {url}")
                            print(f"     Status: {status} - Remote Config is publicly accessible for any authenticated user")
                        else:
                            print(f"  {LIME}[+]{RESET} PUBLIC DATABASE: {url}")
                            print(f"     Status: {status} - Database is publicly accessible for any authenticated user")
                    elif status in ["401", "403"]:
                        print(f"  {RED}[-]{RESET} STILL PROTECTED: {url}")
                        print(f"     Status: {status} - Permission denied (even with auth)")
                    elif status == "404":
                        print(f"  {RED}[-]{RESET} NOT FOUND: {url}")
                        print(f"     Status: {status} - {message}")
                    else:
                        print(f"  {GREY}[UNK]{RESET} UNKNOWN: {url}")
                        print(f"     Status: {status} - {message}")

        # Clear authenticated results after displaying them
        self.all_authenticated_results.clear()

    def _display_verbose_authenticated_results(self, results: Dict[str, Dict[str, str]]):
        """Display authenticated results in verbose format during individual project scanning."""
        if self.authenticated_results:
            print(f"{BLUE}[AUTH]{RESET} Authentication retry results:\n")
            for url, auth_result in self.authenticated_results.items():
                # Only show authenticated results for URLs that were actually tested in this project
                if url in results:
                    status = auth_result.get("status", "unknown")
                    security = auth_result.get("security", "unknown")
                    message = auth_result.get("message", "No message")

                    print(f"URL: {url} (authenticated)")
                    print(f"Status: {status}")
                    print(f"Response: {message}")

                    # Show response content if available
                    if auth_result.get("response_content"):
                        print(f"Content: {auth_result['response_content']}\n")  # Add newline after content for better readability

                    # Add status-specific messages for authenticated results
                    if status == "200":
                        # Check if this is Firestore and handle empty collections specially
                        if "firestore" in url.lower():
                            response_content = auth_result.get("response_content", "")
                            try:
                                import json
                                content_json = json.loads(response_content) if response_content else {}
                                if content_json == {} or content_json.get("documents") == []:
                                    # Empty collection - show database accessible but collection doesn't exist
                                    print(f"{YELLOW}[!]{RESET} PUBLIC FIRESTORE DATABASE (AUTHENTICATED) - Database is publicly accessible with authentication, but this collection doesn't exist (use --fuzz-collections)\n")
                                else:
                                    # Collection has content
                                    print(f"{GREEN}[+]{RESET} PUBLIC ACCESS (AUTHENTICATED) - Resource is publicly accessible with authentication\n") 
                            except (json.JSONDecodeError, ValueError):
                                # If we can't parse JSON, fall back to generic message
                                print(f"{GREEN}[+]{RESET} PUBLIC ACCESS (AUTHENTICATED) - Resource is publicly accessible with authentication\n")
                        else:
                            # Non-Firestore services
                            print(f"{GREEN}[+]{RESET} PUBLIC ACCESS (AUTHENTICATED) - Resource is publicly accessible with authentication\n")
                    elif status in ["401", "403"]:
                        print(f"{RED}[-]{RESET} STILL PROTECTED - Resource remains protected even with authentication")
                    elif status == "404":
                        print(f"{RED}[-]{RESET} NOT FOUND - Resource not found")
                    else:
                        print(f"{YELLOW}[?]{RESET} UNKNOWN - Unexpected response: {status}\n")

    def _get_status_message(
        self,
        status: str,
        security: str,
        message: str,
        result: Dict[str, str],
        resource_type: str = "database",
        colorize: bool = True,
    ) -> str:
        """Get the appropriate status message for display.

        Args:
            status: HTTP status code
            security: Security classification
            message: Base message
            result: Full result dictionary
            resource_type: Type of resource ("database", "storage", "config", or "firestore")
            colorize: Whether to include ANSI color codes (True for console, False for files)

        Returns:
            Formatted status message

        """
        # Conditionally apply colors based on colorize parameter
        if colorize:
            from ..core.config import RED, GREEN, LIME, YELLOW, GREY, GOLD, BLUE, RESET
        else:
            RED = GREEN = LIME = YELLOW = GREY = GOLD = BLUE = RESET = ""
        
        if resource_type == "storage":
            # Storage-specific messages
            if status == STATUS_OK:
                if "write access allowed" in message or "upload successful" in message:
                    return f"{LIME}[+]{RESET} WRITE ACCESS ALLOWED - This storage bucket allows file uploads!"
                return f"{LIME}[+]{RESET} PUBLIC STORAGE - This storage bucket is publicly accessible!"
            if status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]:
                if (
                    "WRITE_FORBIDDEN" in security
                    or "AUTH_REQUIRED" in security
                    or "WRITE_DENIED" in security
                ):
                    return f"{RED}[-]{RESET} WRITE DENIED - Storage bucket requires authentication for write access"
                return f"{RED}[-]{RESET} PERMISSION DENIED - Storage bucket is protected"
            if status == STATUS_PRECONDITION_FAILED:
                if "WRITE_PRECONDITION_FAILED" in security:
                    return f"{RED}[-]{RESET} WRITE PRECONDITION FAILED - Storage bucket write requirements not met"
                return f"{RED}[-]{RESET} PERMISSION ERROR - Service account missing permissions"
            if status == STATUS_BAD_REQUEST:
                if "RULES_VERSION_ERROR" in security:
                    return f"{RED}[-]{RESET} RULES VERSION ERROR - Storage rules version 1 - listing disallowed"
                if "INVALID_NAME" in security:
                    return f"{YELLOW}[!]{RESET}  INVALID FILE NAME - File name format not accepted"
                if "WRITE_DENIED" in security:
                    return (
                        f"{RED}[-]{RESET} WRITE DENIED - Storage bucket does not allow write access"
                    )
                return f"{YELLOW}[!]{RESET}  WARNING - {message}"
            if status == STATUS_TOO_MANY_REQUESTS:
                return f"{YELLOW}[!]{RESET}  WARNING - {message}"
            if status == STATUS_LOCKED:
                return f"{GOLD}[*]{RESET} LOCKED - Storage bucket is locked/deactivated"
            if status == STATUS_NOT_FOUND:
                return f"{RED}[-]{RESET} NOT FOUND - Storage bucket not found"
            return f"{GREY}[UNK]{RESET} UNKNOWN - {message}"
        if resource_type == "config":
            # Remote Config-specific messages
            # Check security cases first before status codes
            if security == "MISSING_CONFIG":
                return f"{RED}[-]{RESET} MISSING CONFIG - API key or App ID not found in APK"
            if security == "NO_CONFIG":
                return f"{GREY}[UNK]{RESET} NO REMOTE CONFIG - App doesn't use Firebase Remote Config"
            if status == STATUS_OK:
                return f"{LIME}[+]{RESET} PUBLIC CONFIG - Remote Config is accessible! Manually check the config for secrets!"
            if status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]:
                return f"{RED}[-]{RESET} PERMISSION DENIED - Remote Config is protected"
            if status == STATUS_BAD_REQUEST or status == STATUS_TOO_MANY_REQUESTS:
                return f"{YELLOW}[!]{RESET}  WARNING - {message}"
            if status == STATUS_NOT_FOUND:
                return f"{RED}[-]{RESET} NOT FOUND - Remote Config not found"
            return f"{GREY}[UNK]{RESET} UNKNOWN - {message}"
        if resource_type == "firestore":
            # Firestore-specific messages
            if security == "DATASTORE_MODE":
                return f"{GREY}[UNK]{RESET} DATASTORE MODE - Firestore database is in Datastore Mode (empty/unused)"
            if status == STATUS_OK:
                # Check if this is a write operation by looking at the message
                if "write access allowed" in message.lower():
                    return f"{LIME}[+]{RESET} WRITE ACCESS ALLOWED - This firestore allows unauthenticated writing to the database."
                if security == "PUBLIC":
                    return f"{LIME}[+]{RESET} PUBLIC FIRESTORE - This Firestore collection is publicly accessible with data!"
                if security == "PUBLIC_DB_NONEXISTENT_COLLECTION":
                    return f"{YELLOW}[!]{RESET}  PUBLIC FIRESTORE DATABASE - Database is publicly accessible, but this collection doesn't exist (use --fuzz-collections)"
                return f"{LIME}[+]{RESET} ACCESSIBLE FIRESTORE - Firestore collection is accessible"
            if status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]:
                return f"{RED}[-]{RESET} PERMISSION DENIED - Firestore collection is protected or project doesn't exist"
            if status == STATUS_BAD_REQUEST or status == STATUS_TOO_MANY_REQUESTS:
                return f"{YELLOW}[!]{RESET}  WARNING - {message}"
            return f"{GREY}[UNK]{RESET} UNKNOWN - {message}"
        # Database-specific messages (default)
        if status == STATUS_OK:
            # Check if this is a write operation by looking at the message
            if "write access allowed" in message.lower() or "data written successfully" in message.lower():
                return f"{LIME}[+]{RESET} WRITE ACCESS ALLOWED - This database allows unauthenticated write access!"
            return f"{LIME}[+]{RESET} PUBLIC DATABASE - This database is publicly accessible!"
        if status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]:
            if (
                "WRITE_FORBIDDEN" in security
                or "AUTH_REQUIRED" in security
                or "WRITE_DENIED" in security
            ):
                return f"{RED}[-]{RESET} WRITE DENIED - Database requires authentication for write access"
            return f"{RED}[-]{RESET} PERMISSION DENIED - Database is protected"
        if status == STATUS_PRECONDITION_FAILED:
            return f"{RED}[-]{RESET} PERMISSION ERROR - Service account missing permissions"
        if status == STATUS_BAD_REQUEST:
            if "RULES_VERSION_ERROR" in security:
                return f"{RED}[-]{RESET} RULES VERSION ERROR - Storage rules version 1 - listing disallowed"
            return f"{YELLOW}[!]{RESET}  WARNING - {message}"
        if status == STATUS_TOO_MANY_REQUESTS:
            return f"{YELLOW}[!]{RESET}  WARNING - {message}"
        if status == STATUS_LOCKED:
            return f"{GOLD}[*]{RESET} LOCKED - Database is locked/deactivated"
        if status == STATUS_NOT_FOUND:
            if "region_redirect" in result:
                return f"{BLUE}[<->]{RESET} Region redirect detected"
            return f"{RED}[-]{RESET} NOT FOUND - Database not found"
        return f"{GREY}[UNK]{RESET} UNKNOWN - {message}"

    def _print_project_results(
        self,
        project_id: str,
        results: Dict[str, Dict[str, str]],
        package_names: List[str] = None,
    ):
        """Print project scan results to console."""
        if package_names:
            if len(package_names) == 1:
                print(
                    f"{ORANGE}Project ID: {project_id}{RESET} (from package: {package_names[0]})"
                )
            else:
                print(
                    f"{ORANGE}Project ID: {project_id}{RESET} (from packages: {', '.join(package_names)})"
                )
        else:
            print(f"{ORANGE}Project ID: {project_id}{RESET}")
        print("=" * 80)

        for url, result in results.items():
            status = result.get("status", "unknown")
            security = result.get("security", "unknown")
            message = result.get("message", "No message")

            # Show the full URL and response details
            print(f"URL: {url}")
            print(f"Status: {status}")
            print(f"Response: {message}")

            # Show response content if available
            if "response_content" in result:
                print(f"Content: {result['response_content']}\n")  # Add newline after content for better readability

            # Add status-specific messages
            resource_type = self._get_resource_type_from_url(url)
            status_message = self._get_status_message(
                status, security, message, result, resource_type
            )
            print(status_message)

            # Check if this URL has an authenticated result and display it immediately
            if url in self.authenticated_results:
                auth_result = self.authenticated_results[url]
                auth_status = auth_result.get("status", "unknown")
                auth_security = auth_result.get("security", "unknown") 
                auth_message = auth_result.get("message", "No message")

                print(f"\n{BLUE}[AUTH]{RESET} Authentication retry result:\n")
                print(f"URL: {url} (authenticated)")
                print(f"Status: {auth_status}")
                print(f"Response: {auth_message}")

                # Show response content if available
                if auth_result.get("response_content"):
                    print(f"Content: {auth_result['response_content']}\n")

                # Add status-specific messages for authenticated results
                auth_status_message = self._get_status_message(
                    auth_status, auth_security, auth_message, auth_result, resource_type
                )
                print(auth_status_message)

            # Print saved file path for config responses if available
            if result.get("saved_file_path"):
                print(f"\n{BLUE}[INF]{RESET} Config response saved to: {result['saved_file_path']}\n")  # Add newlines for readability
            else:
                print()

        # No longer display authenticated results at the end since they're shown inline now

        # Store authenticated results for this project before clearing
        if self.authenticated_results:
            self.all_authenticated_results[project_id] = self.authenticated_results.copy()

        # Clear authenticated results after displaying to avoid carryover to next project
        self.authenticated_results.clear()

    def _save_authenticated_results_to_file_for_project(self, project_id: str, output_file: str):
        """Save authenticated results to file for a specific project using stored results."""
        if project_id not in self.all_authenticated_results:
            return

        auth_results = self.all_authenticated_results[project_id]
        if not auth_results:
            return

        with open(output_file, "a", encoding="utf-8") as f:
            f.write("\n[AUTH] Authentication retry results:\n\n")

            for url, auth_result in auth_results.items():
                status = auth_result.get("status", "unknown")
                security = auth_result.get("security", "unknown")
                message = auth_result.get("message", "No message")

                f.write(f"URL: {url} (authenticated)\n")
                f.write(f"Status: {status}\n")
                f.write(f"Response: {message}\n")

                # Show response content if available
                if auth_result.get("response_content"):
                    f.write(f"Content: {auth_result['response_content']}\n")
                    f.write("\n")  # Add newline after content for better readability

                # Add status-specific messages for authenticated results
                if status == "200":
                    # Check if this is Firestore and handle empty collections specially
                    if "firestore" in url.lower():
                        response_content = auth_result.get("response_content", "")
                        try:
                            import json
                            content_json = json.loads(response_content) if response_content else {}
                            if content_json == {} or content_json.get("documents") == []:
                                # Empty collection - show database accessible but collection doesn't exist
                                f.write("[!] PUBLIC FIRESTORE DATABASE (AUTHENTICATED) - Database is publicly accessible with authentication, but this collection doesn't exist (use --fuzz-collections)\n")
                            else:
                                # Collection has content
                                f.write("[+] PUBLIC ACCESS (AUTHENTICATED) - Resource is publicly accessible with authentication\n")
                        except (json.JSONDecodeError, ValueError):
                            # If we can't parse JSON, fall back to generic message
                            f.write("[+] PUBLIC ACCESS (AUTHENTICATED) - Resource is publicly accessible with authentication\n")
                    else:
                        # Non-Firestore services
                        f.write("[+] PUBLIC ACCESS (AUTHENTICATED) - Resource is publicly accessible with authentication\n")
                elif status in ["401", "403"]:
                    f.write("[-] STILL PROTECTED - Resource remains protected even with authentication\n")
                elif status == "404":
                    f.write("[-] NOT FOUND - Resource not found\n")
                else:
                    f.write("[?] UNKNOWN - Unexpected response: {status}\n")

                f.write("\n")

    def _get_resource_type_from_url(self, url: str) -> str:
        """Determine resource type from URL."""
        if "firestore.googleapis.com" in url:
            return "firestore"
        if "firebasestorage.googleapis.com" in url:
            return "storage"
        if "firebaseremoteconfig.googleapis.com" in url:
            return "config"
        return "database"

    def _count_scan_results(
        self, scan_results: Dict[str, Dict[str, str]], resource_type: str = "database"
    ) -> Dict[str, int]:
        """Count scan results by category.
        
        For databases: Count individual URLs to show all different statuses found
        For other resources: Count per project ID (legacy behavior)

        Args:
            scan_results: Dictionary mapping project IDs to their scan results
            resource_type: Type of resource ("database", "storage", "config", or "firestore")

        Returns:
            Dictionary with counts for each category

        """
        from ..core.config import (
            STATUS_BAD_REQUEST,
            STATUS_FORBIDDEN,
            STATUS_LOCKED,
            STATUS_NOT_FOUND,
            STATUS_OK,
            STATUS_PRECONDITION_FAILED,
            STATUS_TOO_MANY_REQUESTS,
            STATUS_UNAUTHORIZED,
        )

        counts = {
            "total_projects": len(scan_results),
            "public_count": 0,
            "protected_count": 0,
            "not_found_count": 0,
            "no_listing_count": 0,
            "locked_count": 0,
            "rate_limited_count": 0,
            "missing_config_count": 0,
            "no_config_count": 0,
            "datastore_mode_count": 0,
            "other_count": 0,
            "total_open_collections_count": 0,  # For Firestore: count individual open collections
        }

        if resource_type == "database":
            # For databases: Count individual URLs to show all different statuses found
            for project_id, results in scan_results.items():
                for url, result in results.items():
                    status = result["status"]
                    security = result["security"]

                    # Skip region redirects (404 with REGION_REDIRECT) as they're not actual databases
                    if status == STATUS_NOT_FOUND and security == "REGION_REDIRECT":
                        continue

                    if status == STATUS_OK and security not in ["NO_CONFIG"]:
                        counts["public_count"] += 1
                    elif status == STATUS_UNAUTHORIZED:
                        counts["protected_count"] += 1
                    elif status == STATUS_NOT_FOUND:
                        counts["not_found_count"] += 1
                    elif status == STATUS_LOCKED:
                        counts["locked_count"] += 1
                    elif status == STATUS_TOO_MANY_REQUESTS:
                        counts["rate_limited_count"] += 1
                    else:
                        counts["other_count"] += 1
        else:
            # For non-database resources: Count per project ID using prioritization (legacy behavior)
            for project_id, results in scan_results.items():
                # Determine the overall status for this project ID based on all URLs tested
                has_public = False
                has_protected = False
                has_not_found = False
                has_locked = False
                has_rate_limited = False
                has_missing_config = False
                has_no_config = False
                has_datastore_mode = False
                has_no_listing = False
                has_other = False

                for url, result in results.items():
                    status = result["status"]
                    security = result["security"]

                    if status == STATUS_OK and security not in ["NO_CONFIG"]:
                        has_public = True
                        # PUBLIC_AUTH also counts as publicly accessible (just requires auth)
                    elif security == "NO_CONFIG":
                        has_no_config = True
                    elif security == "MISSING_CONFIG":
                        has_missing_config = True
                    elif security == "DATASTORE_MODE":
                        has_datastore_mode = True
                    elif resource_type == "firestore":
                        # For Firestore, 403 means protected or invalid project
                        if status == STATUS_FORBIDDEN or status == STATUS_UNAUTHORIZED:
                            has_protected = True
                        # Handle publicly accessible database with non-existent collection (only if truly public, not auth-only)
                        elif (
                            status == STATUS_OK
                            and security == "PUBLIC_DB_NONEXISTENT_COLLECTION"
                        ):
                            has_public = (
                                True  # Database is publicly accessible (security concern)
                            )

                    # Count individual open collections for Firestore
                    if (
                        resource_type == "firestore"
                        and status == STATUS_OK
                        and security in ["PUBLIC", "PUBLIC_AUTH"]
                    ):
                        counts["total_open_collections_count"] += 1
                    elif status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]:
                        # For storage and config, 401 and 403 are considered protected
                        has_protected = True
                    elif status == STATUS_PRECONDITION_FAILED:
                        if resource_type == "storage":
                            # 412 for storage means bucket doesn't allow listing files, not protected
                            has_no_listing = True
                        else:
                            # 412 is protected for config and other resources
                            has_protected = True
                    elif status == STATUS_BAD_REQUEST:
                        if "RULES_VERSION_ERROR" in security:
                            has_protected = True
                        else:
                            has_other = True
                    elif status == STATUS_NOT_FOUND:
                        if resource_type == "config":
                            has_other = (
                                True  # 404 is not typical for Firebase Remote Config
                            )
                        else:
                            has_not_found = True  # For storage
                    elif status == STATUS_LOCKED:
                        has_other = True  # For storage/config, 423 is unusual
                    elif status == STATUS_TOO_MANY_REQUESTS:
                        has_rate_limited = True
                    else:
                        has_other = True

                # Count this project ID based on priority (most significant status wins)
                if has_public:
                    counts["public_count"] += 1
                elif has_protected:
                    counts["protected_count"] += 1
                elif has_no_listing:
                    counts["no_listing_count"] += 1
                elif has_rate_limited:
                    counts["rate_limited_count"] += 1
                elif has_locked:
                    counts["locked_count"] += 1
                elif has_not_found:
                    counts["not_found_count"] += 1
                elif has_missing_config:
                    counts["missing_config_count"] += 1
                elif has_no_config:
                    counts["no_config_count"] += 1
                elif has_datastore_mode:
                    counts["datastore_mode_count"] += 1
                elif has_other:
                    counts["other_count"] += 1

        return counts

    def _get_summary_labels(self, resource_type: str = "database") -> Dict[str, str]:
        """Get resource-specific summary labels.

        Args:
            resource_type: Type of resource ("database", "storage", "config", or "firestore")

        Returns:
            Dictionary with summary labels

        """
        if resource_type == "storage":
            return {
                "public": "Public storage buckets found",
                "protected": "Protected storage buckets (401/403/400)",
                "no_listing": "Storage does not allow listing files (412)",
                "not_found": "Storage bucket not found (404)",
                "rate_limited": "Rate limited (429)",
                "other": "Other/errors",
                "warning": "public storage bucket(s) found!",
            }
        if resource_type == "config":
            return {
                "public": "Remote configs found",
                "protected": "Protected remote configs (401/403)",
                "missing_config": "Missing config data",
                "no_config": "Apps without Remote Config",
                "rate_limited": "Rate limited (429)",
                "other": "Other/errors",
                "warning": "public remote config(s) found!",
            }
        if resource_type == "firestore":
            return {
                "public": "Projects with publicly accessible Firestore databases",
                "protected": "Protected Firestore collections (403)",
                "datastore_mode": "Projects in Datastore Mode (empty/unused)",
                "rate_limited": "Rate limited (429)",
                "other": "Other/errors",
                "total_open_collections": "Total open collections found",
                "warning": "publicly accessible Firestore database(s) found!",
            }
        return {
            "public": "Public databases found",
            "protected": "Protected databases (401)",
            "not_found": "Database not found (404)",
            "locked": "Locked/deactivated (423)",
            "rate_limited": "Rate limited (429)",
            "other": "Other/errors",
            "warning": "public database(s) found!",
        }

    def _write_scan_results_section(
        self,
        f,
        scan_results: Dict[str, Dict[str, str]],
        section_title: str,
        resource_type: str = "database",
        project_to_packages: Dict[str, List[str]] = None,
    ):
        """Write a section of scan results to a file.

        Args:
            f: File handle to write to
            scan_results: Dictionary mapping project IDs to their scan results
            section_title: Title for this section
            resource_type: Type of resource ("database", "storage", "config", "firestore")
            project_to_packages: Dictionary mapping project IDs to lists of package names

        """
        f.write(f"{section_title}\n")
        f.write("=" * 80 + "\n\n")

        for project_id, results in scan_results.items():
            # Write project ID with package names if available
            if project_to_packages and project_id in project_to_packages:
                package_names = project_to_packages[project_id]
                if len(package_names) == 1:
                    f.write(
                        f"Project ID: {project_id} (from package: {package_names[0]})\n"
                    )
                else:
                    f.write(
                        f"Project ID: {project_id} (from packages: {', '.join(package_names)})\n"
                    )
            else:
                f.write(f"Project ID: {project_id}\n")
            f.write("=" * 80 + "\n")

            for url, result in results.items():
                status = result["status"]
                message = result["message"]
                security = result["security"]

                f.write(f"URL: {url}\n")
                f.write(f"Status: {status}\n")
                f.write(f"Response: {message}\n")

                if "response_content" in result:
                    f.write(f"Content: {result['response_content']}\n")
                    f.write("\n")  # Add newline after content for better readability

                # Add status-specific messages
                status_message = self._get_status_message(
                    status, security, message, result, resource_type, colorize=False
                )
                f.write(f"{status_message}\n")
                f.write("\n")

            f.write("\n")

    def _save_open_only_results(
        self,
        all_results: Dict[str, Dict[str, str]],
        output_file: str,
        resource_type: str = "database",
        package_project_ids: Dict[str, Set[str]] = None,
        print_warning: bool = True,
    ):
        """Save only open/public results to a separate file.

        Args:
            all_results: Dictionary mapping project IDs to their scan results
            output_file: Base output file path (will append resource type)
            resource_type: Type of resource ("database", "storage", "config", "firestore")
            package_project_ids: Dictionary mapping package names to sets of project IDs
            print_warning: Whether to print warning message immediately

        Returns:
            Warning message string if print_warning is False, None otherwise

        """
        from pathlib import Path

        # Extract public/open results from original scan results
        open_results = {}
        for project_id, results in all_results.items():
            for url, result in results.items():
                status = result.get("status", "unknown")
                security = result.get("security", "unknown")

                # Consider it "open" if status is 200 and it's not a NO_CONFIG response
                if status == STATUS_OK and security not in ["NO_CONFIG"]:
                    if project_id not in open_results:
                        open_results[project_id] = {}
                    open_results[project_id][url] = result

        # Also include authenticated accessible results as "open"
        for project_id, auth_results in self.all_authenticated_results.items():
            for url, auth_result in auth_results.items():
                status = auth_result.get("status", "unknown")
                if status == "200":  # Authenticated accessible = open
                    if project_id not in open_results:
                        open_results[project_id] = {}
                    # Create a combined result entry for the open file
                    open_results[project_id][url] = {
                        "status": status,
                        "message": "Accessible with authentication",
                        "accessible": True,
                        "security": "PUBLIC_AUTH",
                        "response_content": auth_result.get("response_content", "")
                    }

        if not open_results:
            return None

        # Create reverse mapping from project ID to package names
        project_to_packages = {}
        if package_project_ids:
            for package_name, project_id_set in package_project_ids.items():
                for project_id in project_id_set:
                    if project_id not in project_to_packages:
                        project_to_packages[project_id] = []
                    project_to_packages[project_id].append(package_name)

        # Create filename for open-only results
        base_path = Path(output_file)
        open_file = (
            base_path.parent
            / f"{base_path.stem}_open_only.txt"
        )

        with open(open_file, "w", encoding="utf-8") as f:
            resource_title = resource_type.upper()
            f.write(f"OPEN/PUBLIC {resource_title} RESULTS ONLY\n")
            f.write("=" * 80 + "\n")
            f.write(
                f"Found {len(open_results)} open {resource_type}(s) with public access\n\n"
            )

            for project_id, results in open_results.items():
                # Write project ID with package names if available
                package_names = project_to_packages.get(project_id, [])
                if package_names:
                    if len(package_names) == 1:
                        f.write(
                            f"Project ID: {project_id} (from package: {package_names[0]})\n"
                        )
                    else:
                        f.write(
                            f"Project ID: {project_id} (from packages: {', '.join(package_names)})\n"
                        )
                else:
                    f.write(f"Project ID: {project_id}\n")
                f.write("=" * 80 + "\n")

                for url, result in results.items():
                    status = result["status"]
                    message = result["message"]
                    security = result["security"]

                    f.write(f"URL: {url}\n")
                    f.write(f"Status: {status}\n")
                    f.write(f"Response: {message}\n")

                    if "response_content" in result:
                        f.write(f"Content: {result['response_content']}\n")

                    status_message = self._get_status_message(
                        status, security, message, result, resource_type
                    )
                    f.write(f"{status_message}\n")
                    f.write("\n")

                f.write("\n")

            # Add summary
            f.write("\n" + "=" * 80 + "\n")
            f.write("SUMMARY OF OPEN/PUBLIC RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Total open {resource_type}s found: {len(open_results)}\n")
            f.write(
                f"Total open URLs found: {sum(len(results) for results in open_results.values())}\n"
            )

            # List all open project IDs
            f.write(f"\nOpen {resource_type} project IDs:\n")
            for project_id in sorted(open_results.keys()):
                package_names = project_to_packages.get(project_id, [])
                if package_names:
                    f.write(
                        f"- {project_id} (from packages: {', '.join(package_names)})\n"
                    )
                else:
                    f.write(f"- {project_id}\n")

        # For databases, count individual URLs; for other resources, count projects
        if resource_type == "database":
            total_open_urls = sum(len(results) for results in open_results.values())
            warning_message = f"{YELLOW}[!]{RESET}  {total_open_urls} open {resource_type}(s) found! Details saved to {open_file}"
        else:
            warning_message = f"{YELLOW}[!]{RESET}  {len(open_results)} open {resource_type}(s) found! Details saved to {open_file}"

        if print_warning:
            print(warning_message)
            return None
        return warning_message

    # Print methods for display and analysis (shared by all scanners)
    def print_scan_results(
        self, scan_results, scan_type="DATABASES", package_project_ids=None
    ):
        """Print scan results to console with color coding."""
        # Map scan types to display names
        type_mapping = {
            "DATABASES": "FIREBASE REALTIME DATABASE READ RESULTS",
            "DATABASE WRITE": "FIREBASE REALTIME DATABASE WRITE RESULTS",
            "STORAGE": "FIREBASE STORAGE READ RESULTS",
            "STORAGE WRITE": "FIREBASE STORAGE WRITE RESULTS",
            "CONFIG": "FIREBASE REMOTE CONFIG READ RESULTS",
            "FIRESTORE": "FIREBASE FIRESTORE READ RESULTS"
        }

        base_display_name = type_mapping.get(scan_type, f"FIREBASE {scan_type} RESULTS")
        display_name = f"{RED}[UNAUTH]{RESET} {ORANGE}{base_display_name}{RESET}"
        print("\n" + "=" * 80)
        print(display_name)
        print("=" * 80)

        # Create reverse mapping from project ID to package names
        project_to_packages = {}
        if package_project_ids:
            for package_name, pids in package_project_ids.items():
                for pid in pids:
                    if pid not in project_to_packages:
                        project_to_packages[pid] = []
                    project_to_packages[pid].append(package_name)

        for project_id, results in scan_results.items():
            # Display project ID with package names if available
            if project_to_packages and project_id in project_to_packages:
                package_names = project_to_packages[project_id]
                if len(package_names) == 1:
                    print(
                        f"\n{ORANGE}Project ID: {project_id} (from package: {package_names[0]}){RESET}"
                    )
                else:
                    print(
                        f"\n{ORANGE}Project ID: {project_id} (from packages: {', '.join(package_names)}){RESET}"
                    )
            else:
                print(f"\n{ORANGE}Project ID: {project_id}{RESET}")
            print("-" * 50)

            for url, result in results.items():
                status = result["status"]
                message = result["message"]
                security = result["security"]

                # Color coding based on status and security
                # Special handling for remote config NO_CONFIG responses
                if "firebaseremoteconfig" in url.lower() and security == "NO_CONFIG":
                    print(f"  {GREY}[UNK]{RESET} NO REMOTE CONFIG: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_OK:
                    if "storage" in url.lower():
                        print(f"  {LIME}[+]{RESET} PUBLIC STORAGE: {url}")
                    elif "firestore" in url.lower():
                        if security == "PUBLIC_DB_NONEXISTENT_COLLECTION":
                            print(f"  {YELLOW}[!]{RESET}  PUBLIC FIRESTORE DATABASE: {url}")
                        else:
                            print(f"  {LIME}[+]{RESET} PUBLIC FIRESTORE: {url}")
                    elif "firebaseremoteconfig" in url.lower():
                        print(f"  {LIME}[+]{RESET} PUBLIC REMOTE CONFIG: {url}")
                    else:
                        print(f"  {LIME}[+]{RESET} PUBLIC DATABASE: {url}")
                    print(f"     Status: {status} - {message}")
                elif (
                    status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]
                    or status == STATUS_PRECONDITION_FAILED
                ):
                    print(f"  {RED}[-]{RESET} PROTECTED: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_BAD_REQUEST and "RULES_VERSION_ERROR" in security:
                    print(f"  {RED}[-]{RESET} RULES VERSION ERROR: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_NOT_FOUND:
                    if security == "REGION_REDIRECT":
                        print(f"  {BLUE}[<->]{RESET} REGION REDIRECT: {url}")
                    else:
                        print(f"  {RED}[-]{RESET} NOT FOUND: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_LOCKED:
                    print(f"  {GOLD}[*]{RESET} LOCKED: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_TOO_MANY_REQUESTS:
                    print(f"  {YELLOW}[!]{RESET}  RATE LIMITED: {url}")
                    print(f"     Status: {status} - {message}")
                else:
                    print(f"  {GREY}[UNK]{RESET} UNKNOWN: {url}")
                    print(f"     Status: {status} - {message}")

        # Display authenticated results and clear them
        self._display_and_clear_authenticated_results(scan_results, scan_type)

        # Summary
        print("\n" + "=" * 80)
        # Print the summary (no output_dir available here, so will use default "./remote_config_results")
        self.print_scan_summary(scan_results, scan_type)

    def print_scan_details(
        self, scan_results, scan_type="DATABASES", package_project_ids=None
    ):
        """Print only the detailed scan results to console (without summary)."""
        # Map scan types to display names
        type_mapping = {
            "DATABASES": "FIREBASE REALTIME DATABASE READ RESULTS",
            "DATABASE WRITE": "FIREBASE REALTIME DATABASE WRITE RESULTS",
            "STORAGE": "FIREBASE STORAGE READ RESULTS",
            "STORAGE WRITE": "FIREBASE STORAGE WRITE RESULTS",
            "CONFIG": "FIREBASE REMOTE CONFIG READ RESULTS",
            "FIRESTORE": "FIREBASE FIRESTORE READ RESULTS"
        }

        base_display_name = type_mapping.get(scan_type, f"FIREBASE {scan_type} RESULTS")
        display_name = f"{RED}[UNAUTH]{RESET} {ORANGE}{base_display_name}{RESET}"
        print("\n" + "=" * 80)
        print(display_name)
        print("=" * 80)

        # Create reverse mapping from project ID to package names
        project_to_packages = {}
        if package_project_ids:
            for package_name, pids in package_project_ids.items():
                for pid in pids:
                    if pid not in project_to_packages:
                        project_to_packages[pid] = []
                    project_to_packages[pid].append(package_name)

        for project_id, results in scan_results.items():
            # Display project ID with package names if available
            if project_to_packages and project_id in project_to_packages:
                package_names = project_to_packages[project_id]
                if len(package_names) == 1:
                    print(
                        f"\n{ORANGE}Project ID: {project_id} (from package: {package_names[0]}){RESET}"
                    )
                else:
                    print(
                        f"\n{ORANGE}Project ID: {project_id} (from packages: {', '.join(package_names)}){RESET}"
                    )
            else:
                print(f"\n{ORANGE}Project ID: {project_id}{RESET}")
            print("-" * 50)

            for url, result in results.items():
                status = result["status"]
                message = result["message"]
                security = result["security"]

                # Color coding based on status and security
                # Special handling for remote config NO_CONFIG responses
                if "firebaseremoteconfig" in url.lower() and security == "NO_CONFIG":
                    print(f"  {GREY}[UNK]{RESET} NO REMOTE CONFIG: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_OK:
                    if "storage" in url.lower():
                        print(f"  {LIME}[+]{RESET} PUBLIC STORAGE: {url}")
                    elif "firestore" in url.lower():
                        if security == "PUBLIC_DB_NONEXISTENT_COLLECTION":
                            print(f"  {YELLOW}[!]{RESET}  PUBLIC FIRESTORE DATABASE: {url}")
                        else:
                            print(f"  {LIME}[+]{RESET} PUBLIC FIRESTORE: {url}")
                    elif "firebaseremoteconfig" in url.lower():
                        print(f"  {LIME}[+]{RESET} PUBLIC REMOTE CONFIG: {url}")
                    else:
                        print(f"  {LIME}[+]{RESET} PUBLIC DATABASE: {url}")
                    print(f"     Status: {status} - {message}")
                elif (
                    status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]
                    or status == STATUS_PRECONDITION_FAILED
                ):
                    print(f"  {RED}[-]{RESET} PROTECTED: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_BAD_REQUEST and "RULES_VERSION_ERROR" in security:
                    print(f"  {RED}[-]{RESET} RULES VERSION ERROR: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_NOT_FOUND:
                    if security == "REGION_REDIRECT":
                        print(f"  {BLUE}[<->]{RESET} REGION REDIRECT: {url}")
                    else:
                        print(f"  {RED}[-]{RESET} NOT FOUND: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_LOCKED:
                    print(f"  {GOLD}[*]{RESET} LOCKED: {url}")
                    print(f"     Status: {status} - {message}")
                elif status == STATUS_TOO_MANY_REQUESTS:
                    print(f"  {YELLOW}[!]{RESET}  RATE LIMITED: {url}")
                    print(f"     Status: {status} - {message}")
                else:
                    print(f"  {GREY}[UNK]{RESET} UNKNOWN: {url}")
                    print(f"     Status: {status} - {message}")

        # Display authenticated results and clear them
        self._display_and_clear_authenticated_results(scan_results, scan_type)

    def print_scan_summary(self, scan_results, scan_type="DATABASES", output_dir=None):
        """Print only the scan summary (counts and totals) to console."""
        # Map scan types to display names
        type_mapping = {
            "DATABASES": "FIREBASE REALTIME DATABASE READ",
            "STORAGE": "FIREBASE STORAGE READ",
            "STORAGE WRITE": "FIREBASE STORAGE WRITE",
            "CONFIG": "FIREBASE REMOTE CONFIG READ",
            "FIRESTORE": "FIREBASE FIRESTORE READ",
            "FIRESTORE WRITE": "FIREBASE FIRESTORE WRITE",
            "REALTIME DATABASE WRITE": "FIREBASE REALTIME DATABASE WRITE"
        }

        display_name = type_mapping.get(scan_type, scan_type)
        print(f"{RED}[UNAUTH]{RESET} {ORANGE}SCAN SUMMARY {display_name}{RESET}")
        print("=" * 80)

        if "STORAGE" in scan_type:
            resource_type = "storage"
        elif "CONFIG" in scan_type:
            resource_type = "config"
        elif "FIRESTORE" in scan_type:
            resource_type = "firestore"
        else:
            resource_type = "database"
        counts = self._count_scan_results(scan_results, resource_type)
        labels = self._get_summary_labels(resource_type)

        print(f"Total projects scanned: {counts['total_projects']}")
        print(f"{labels['public']}: {counts['public_count']}")
        print(f"{labels['protected']}: {counts['protected_count']}")
        if resource_type not in [
            "config",
            "firestore",
        ]:  # Config and Firestore don't have "not found" status
            print(f"{labels['not_found']}: {counts['not_found_count']}")

        # Add resource-specific counts
        if resource_type == "config":
            print(f"{labels['missing_config']}: {counts['missing_config_count']}")
            print(f"{labels['no_config']}: {counts['no_config_count']}")
        elif resource_type == "database":
            print(f"{labels['locked']}: {counts['locked_count']}")
        elif resource_type == "storage":
            print(f"{labels['no_listing']}: {counts['no_listing_count']}")
        elif resource_type == "firestore":
            print(
                f"{labels['total_open_collections']}: {counts['total_open_collections_count']}"
            )

        if counts["rate_limited_count"] > 0:
            print(f"{labels['rate_limited']}: {counts['rate_limited_count']}")
        print(f"{labels['other']}: {counts['other_count']}")

        if counts["public_count"] > 0:
            if resource_type == "storage":
                resource_word = "storage buckets"
            elif resource_type == "config":
                resource_word = "remote configs"
            elif resource_type == "firestore":
                resource_word = "Firestore databases"
            else:
                resource_word = "databases"
            print(
                f"\n{YELLOW}[!]{RESET}  WARNING: {counts['public_count']} public {resource_word} found!"
            )

            # Check if any results are auth-only accessible
            has_auth_only = False
            has_no_auth = False
            for project_results in scan_results.values():
                for result in project_results.values():
                    if result.get("security") == "PUBLIC_AUTH":
                        has_auth_only = True
                    elif result.get("security") in ["PUBLIC", "PUBLIC_DB_NONEXISTENT_COLLECTION"]:
                        has_no_auth = True

            if has_auth_only and not has_no_auth:
                print(f"{YELLOW}[!]{RESET}  These {resource_word} are accessible with authentication.")
            elif has_auth_only and has_no_auth:
                print(f"{YELLOW}[!]{RESET}  These {resource_word} are accessible (some without authentication, some require authentication).")
            else:
                print(f"{YELLOW}[!]{RESET}  These {resource_word} are accessible without authentication.")

            # Add trufflehog command for config scans
            if resource_type == "config":
                print(f"{YELLOW}[!]{RESET}  It is recommended to scan all configs for secrets with Gitleaks and Trufflehog using the following commands:")
                print(f"{YELLOW}[!]{RESET}  trufflehog filesystem remote_config_results")
                print(f"{YELLOW}[!]{RESET}  gitleaks dir remote_config_results -v")

        print("=" * 80)

    def save_combined_scan_results(
        self,
        db_scan_results=None,
        storage_scan_results=None,
        config_scan_results=None,
        firestore_scan_results=None,
        storage_write_results=None,
        rtdb_write_results=None,
        firestore_write_results=None,
        output_file=None,
        package_project_ids=None,
        print_warnings=True,
    ):
        """Save combined scan results from multiple scanners."""
        warning_messages = []

        with open(output_file, "w", encoding="utf-8") as f:
            # Create reverse mapping from project ID to package names
            project_to_packages = {}
            if package_project_ids:
                for package_name, pids in package_project_ids.items():
                    for pid in pids:
                        if pid not in project_to_packages:
                            project_to_packages[pid] = []
                        project_to_packages[pid].append(package_name)

            # Determine what services were scanned for the header
            services_scanned = []
            if db_scan_results:
                services_scanned.append("Realtime Database read")
            if storage_scan_results:
                services_scanned.append("Storage read")
            if config_scan_results:
                services_scanned.append("Remote Config read")
            if firestore_scan_results:
                services_scanned.append("Firestore read")
            if storage_write_results:
                services_scanned.append("Storage Write")
            if firestore_write_results:
                services_scanned.append("Firestore Write")
            if rtdb_write_results:
                services_scanned.append("Realtime Database write")

            header = f"Firebase Combined Scan Results ({' + '.join(services_scanned)})"
            f.write(header + "\n")
            f.write("=" * 80 + "\n\n")

            # Database results
            # Realtime Database results
            if db_scan_results:
                self._write_scan_results_section(
                    f,
                    db_scan_results,
                    "REALTIME DATABASE READ RESULTS",
                    "database",
                    project_to_packages,
                )

            # Storage results
            if storage_scan_results:
                self._write_scan_results_section(
                    f,
                    storage_scan_results,
                    "STORAGE READ RESULTS",
                    "storage",
                    project_to_packages,
                )

            # Remote Config results
            if config_scan_results:
                self._write_scan_results_section(
                    f,
                    config_scan_results,
                    "REMOTE CONFIG READ RESULTS",
                    "config",
                    project_to_packages,
                )

            # Firestore results
            if firestore_scan_results:
                self._write_scan_results_section(
                    f,
                    firestore_scan_results,
                    "FIRESTORE READ RESULTS",
                    "firestore",
                    project_to_packages,
                )

            # Storage write results
            if storage_write_results:
                self._write_scan_results_section(
                    f,
                    storage_write_results,
                    "FIREBASE STORAGE WRITE RESULTS",
                    "storage",
                    project_to_packages,
                )

            # RTDB write results
            if rtdb_write_results:
                self._write_scan_results_section(
                    f,
                    rtdb_write_results,
                    "FIREBASE REALTIME DATABASE WRITE RESULTS",
                    "database",
                    project_to_packages,
                )

            # Firestore write results
            if firestore_write_results:
                self._write_scan_results_section(
                    f,
                    firestore_write_results,
                    "FIRESTORE WRITE RESULTS",
                    "firestore",
                    project_to_packages,
                )

            # Combined summary (matches console output when using --read-all)
            f.write("\n[UNAUTH] SCAN SUMMARY\n")
            f.write("=" * 80 + "\n")

            # Get counts for all scan types and calculate totals
            total_public = 0
            scan_data = []

            if db_scan_results:
                db_counts = self._count_scan_results(db_scan_results, "database")
                db_labels = self._get_summary_labels("database")
                scan_data.append(("DATABASES", db_counts, db_labels, "database"))
                total_public += db_counts["public_count"]

            if storage_scan_results:
                storage_counts = self._count_scan_results(
                    storage_scan_results, "storage"
                )
                storage_labels = self._get_summary_labels("storage")
                scan_data.append(("STORAGE", storage_counts, storage_labels, "storage"))
                total_public += storage_counts["public_count"]

            if config_scan_results:
                config_counts = self._count_scan_results(config_scan_results, "config")
                config_labels = self._get_summary_labels("config")
                scan_data.append(
                    ("REMOTE CONFIG", config_counts, config_labels, "config")
                )
                total_public += config_counts["public_count"]

            if firestore_scan_results:
                firestore_counts = self._count_scan_results(
                    firestore_scan_results, "firestore"
                )
                firestore_labels = self._get_summary_labels("firestore")
                scan_data.append(
                    ("FIRESTORE", firestore_counts, firestore_labels, "firestore")
                )
                total_public += firestore_counts["public_count"]

            if storage_write_results:
                storage_write_counts = self._count_scan_results(
                    storage_write_results, "storage"
                )
                storage_write_labels = self._get_summary_labels("storage")
                scan_data.append(
                    (
                        "STORAGE WRITE RESULTS",
                        storage_write_counts,
                        storage_write_labels,
                        "storage",
                    )
                )
                total_public += storage_write_counts["public_count"]

            if rtdb_write_results:
                rtdb_write_counts = self._count_scan_results(
                    rtdb_write_results, "database"
                )
                rtdb_write_labels = self._get_summary_labels("database")
                scan_data.append(
                    (
                        "RTDB WRITE RESULTS",
                        rtdb_write_counts,
                        rtdb_write_labels,
                        "database",
                    )
                )
                total_public += rtdb_write_counts["public_count"]

            if firestore_write_results:
                firestore_write_counts = self._count_scan_results(
                    firestore_write_results, "firestore"
                )
                firestore_write_labels = self._get_summary_labels("firestore")
                scan_data.append(
                    (
                        "FIRESTORE WRITE RESULTS",
                        firestore_write_counts,
                        firestore_write_labels,
                        "firestore",
                    )
                )
                total_public += firestore_write_counts["public_count"]

            # Write summary for each scan type (individual summaries like console)
            for section_name, counts, labels, resource_type in scan_data:
                f.write(f"{section_name}:\n")
                f.write(f"  Total projects scanned: {counts['total_projects']}\n")
                f.write(f"  {labels['public']}: {counts['public_count']}\n")
                f.write(f"  {labels['protected']}: {counts['protected_count']}\n")

                # Only show not_found for database and storage
                if resource_type in ["database", "storage"]:
                    f.write(f"  {labels['not_found']}: {counts['not_found_count']}\n")
                elif resource_type == "config":
                    f.write(
                        f"  {labels['missing_config']}: {counts['missing_config_count']}\n"
                    )
                    f.write(f"  {labels['no_config']}: {counts['no_config_count']}\n")
                elif resource_type == "firestore":
                    f.write(
                        f"  {labels['total_open_collections']}: {counts['total_open_collections_count']}\n"
                    )

                # Add resource-specific counts for databases
                if resource_type == "database":
                    f.write(f"  {labels['locked']}: {counts['locked_count']}\n")

                if counts["rate_limited_count"] > 0:
                    f.write(
                        f"  {labels['rate_limited']}: {counts['rate_limited_count']}\n"
                    )
                f.write(f"  {labels['other']}: {counts['other_count']}\n")

                # Add warnings for public resources
                if counts["public_count"] > 0:
                    if resource_type == "storage":
                        resource_word = "storage buckets"
                    elif resource_type == "config":
                        resource_word = "remote configs"
                    elif resource_type == "firestore":
                        resource_word = "Firestore databases"
                    else:
                        resource_word = "databases"
                    f.write(
                        f"  WARNING: {counts['public_count']} public {resource_word} found!\n"
                    )
                    f.write(
                        f"  These {resource_word} are accessible without authentication.\n"
                    )

                f.write("\n")

            # Overall warning
            if total_public > 0:
                f.write(
                    f"OVERALL WARNING: {total_public} total public Firebase resources found!\n"
                )
                f.write("These resources are accessible without authentication.\n")

        return warning_messages

    @abstractmethod
    def scan_project_id(self, project_id: str) -> Dict[str, str]:
        """Scan a single project ID."""

    @abstractmethod
    def scan_project_ids(
        self, project_ids: Set[str], **kwargs
    ) -> Dict[str, Dict[str, str]]:
        """Scan multiple project IDs."""
