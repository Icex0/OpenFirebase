"""Firebase Authentication Module for OpenFirebase

Handles Firebase authentication using the Identity Toolkit API for
authenticated scanning capabilities.
"""

import base64
import json
from typing import Dict, List, Optional, Tuple

import requests

from ..handlers.auth_data_handler import AuthDataHandler
from .config import BLUE, GREEN, RED, RESET, YELLOW


class FirebaseAuth:
    """Handles Firebase authentication via Identity Toolkit API."""

    def __init__(self, timeout: int = 10, proxy: str = None):
        """Initialize Firebase authentication handler.

        Args:
            timeout: Request timeout in seconds
            proxy: Proxy URL for HTTP requests

        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json"
        })

        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
            # Disable SSL verification for intercepting proxies
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Store authentication tokens per project
        self._auth_tokens: Dict[str, str] = {}
        self._auth_failures: Dict[str, str] = {}

        # Store JWT aud validation results
        self._jwt_project_mapping: Dict[str, str] = {}  # Maps project_id -> aud_project_id

    def create_account_and_get_token(
        self,
        project_id: str,
        api_key: str,
        email: str,
        password: str,
        package_name: Optional[str] = None,
        cert_sha1: Optional[str] = None
    ) -> Optional[str]:
        """Create a Firebase account and return the ID token.

        Args:
            project_id: Firebase project ID
            api_key: Firebase API key (Google_API_key)
            email: Email address for account creation
            password: Password for account creation
            package_name: Android package name for X-Android-Package header
            cert_sha1: Android certificate SHA-1 hash for X-Android-Cert header

        Returns:
            ID token if successful, None if failed

        """
        # Check if we already have a token for this project
        if project_id in self._auth_tokens:
            return self._auth_tokens[project_id]

        # Check if we already failed for this project
        if project_id in self._auth_failures:
            return None

        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            print(f"{BLUE}[AUTH]{RESET} Attempting to create Firebase account for project: {project_id}")

            # Prepare headers including Android identification headers
            headers = {}
            if package_name:
                headers["X-Android-Package"] = package_name
            if cert_sha1:
                headers["X-Android-Cert"] = cert_sha1

            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                try:
                    response_data = response.json()
                    id_token = response_data.get("idToken")

                    if id_token:
                        self._auth_tokens[project_id] = id_token
                        return id_token
                    print(f"{RED}[AUTH]{RESET} No idToken in response for project {project_id}")
                    self._auth_failures[project_id] = "No idToken in response"
                    return None

                except ValueError as e:
                    print(f"{RED}[AUTH]{RESET} Failed to parse JSON response for project {project_id}: {e}")
                    self._auth_failures[project_id] = f"JSON parse error: {e}"
                    return None

            elif response.status_code == 400:
                # Check for specific error messages
                try:
                    error_data = response.json()
                    error_message = error_data.get("error", {}).get("message", "Unknown error")
                    if "EMAIL_EXISTS" in error_message:
                        print(f"{YELLOW}[AUTH]{RESET} Email already exists for project {project_id}, trying sign-in...")
                        return self._sign_in_existing_account(project_id, api_key, email, password, package_name, cert_sha1)
                    restriction_indicator = ""
                    if "Android client application" in error_message and "are blocked" in error_message:
                        restriction_indicator = " [RESTRICTED TO ANDROID APP]"
                    print(f"{RED}[AUTH]{RESET} Account creation failed for project {project_id}: {error_message}{restriction_indicator}")
                    self._auth_failures[project_id] = f"{error_message}{restriction_indicator}"
                    # Try anonymous sign-in
                    return self._try_anonymous_signin(project_id, api_key, package_name, cert_sha1)
                except ValueError:
                    print(f"{RED}[AUTH]{RESET} Account creation failed for project {project_id} (HTTP 400)")
                    self._auth_failures[project_id] = "HTTP 400 error"
                    # Try anonymous sign-in
                    return self._try_anonymous_signin(project_id, api_key, package_name, cert_sha1)

            else:
                # Check for specific error messages in non-400 responses
                restriction_indicator = ""
                try:
                    error_data = response.json()
                    error_message = error_data.get("error", {}).get("message", "")
                    if "Android client application" in error_message and "are blocked" in error_message:
                        restriction_indicator = " [RESTRICTED TO ANDROID APP]"
                except (ValueError, KeyError):
                    # Not JSON or no error message field
                    pass

                print(f"{RED}[AUTH]{RESET} Account creation failed for project {project_id} (HTTP {response.status_code}){restriction_indicator}")
                self._auth_failures[project_id] = f"HTTP {response.status_code}{restriction_indicator}"
                # Try anonymous sign-in
                return self._try_anonymous_signin(project_id, api_key, package_name, cert_sha1)

        except requests.exceptions.RequestException as e:
            print(f"{RED}[AUTH]{RESET} Network error creating account for project {project_id}: {e}")
            self._auth_failures[project_id] = f"Network error: {e}"
            # Try anonymous sign-in
            return self._try_anonymous_signin(project_id, api_key, package_name, cert_sha1)

    def _sign_in_existing_account(
        self,
        project_id: str,
        api_key: str,
        email: str,
        password: str,
        package_name: Optional[str] = None,
        cert_sha1: Optional[str] = None
    ) -> Optional[str]:
        """Sign in to existing Firebase account.

        Args:
            project_id: Firebase project ID
            api_key: Firebase API key
            email: Email address
            password: Password
            package_name: Android package name for X-Android-Package header
            cert_sha1: Android certificate SHA-1 hash for X-Android-Cert header

        Returns:
            ID token if successful, None if failed

        """
        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            # Prepare headers including Android identification headers
            headers = {}
            if package_name:
                headers["X-Android-Package"] = package_name
            if cert_sha1:
                headers["X-Android-Cert"] = cert_sha1

            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                try:
                    response_data = response.json()
                    id_token = response_data.get("idToken")

                    if id_token:
                        self._auth_tokens[project_id] = id_token
                        return id_token
                    print(f"{RED}[AUTH]{RESET} No idToken in sign-in response for project {project_id}")
                    self._auth_failures[project_id] = "No idToken in sign-in response"
                    return None

                except ValueError as e:
                    print(f"{RED}[AUTH]{RESET} Failed to parse sign-in JSON response for project {project_id}: {e}")
                    self._auth_failures[project_id] = f"Sign-in JSON parse error: {e}"
                    return None
            else:
                # Try to extract detailed error message from response
                restriction_indicator = ""
                try:
                    error_data = response.json()
                    error_message = error_data.get("error", {}).get("message", "Unknown error")
                    if "Android client application" in error_message and "are blocked" in error_message:
                        restriction_indicator = " [RESTRICTED TO ANDROID APP]"
                    print(f"{RED}[AUTH]{RESET} Sign-in failed for project {project_id}: {error_message} (HTTP {response.status_code}){restriction_indicator}")
                    self._auth_failures[project_id] = f"Sign-in failed: {error_message}{restriction_indicator}"
                    return None
                except ValueError:
                    print(f"{RED}[AUTH]{RESET} Sign-in failed for project {project_id} (HTTP {response.status_code})")
                    self._auth_failures[project_id] = f"Sign-in HTTP {response.status_code}"
                    return None

        except requests.exceptions.RequestException as e:
            print(f"{RED}[AUTH]{RESET} Network error signing in for project {project_id}: {e}")
            self._auth_failures[project_id] = f"Sign-in network error: {e}"
            return None

    def _try_anonymous_signin(
        self,
        project_id: str,
        api_key: str,
        package_name: Optional[str] = None,
        cert_sha1: Optional[str] = None
    ) -> Optional[str]:
        """Try anonymous sign-in for Firebase authentication.

        Args:
            project_id: Firebase project ID
            api_key: Firebase API key
            package_name: Android package name for X-Android-Package header
            cert_sha1: Android certificate SHA-1 hash for X-Android-Cert header

        Returns:
            ID token if successful, None if failed

        """
        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
            payload = {
                "returnSecureToken": True
            }

            print(f"{BLUE}[AUTH]{RESET} Trying anonymous sign-in for project: {project_id}")

            # Prepare headers including Android identification headers
            headers = {}
            if package_name:
                headers["X-Android-Package"] = package_name
            if cert_sha1:
                headers["X-Android-Cert"] = cert_sha1

            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                try:
                    response_data = response.json()
                    id_token = response_data.get("idToken")

                    if id_token:
                        self._auth_tokens[project_id] = id_token
                        print(f"{GREEN}[AUTH]{RESET} Anonymous sign-in successful for project {project_id}")
                        return id_token
                    print(f"{RED}[AUTH]{RESET} No idToken in anonymous sign-in response for project {project_id}")
                    return None

                except ValueError as e:
                    print(f"{RED}[AUTH]{RESET} Failed to parse anonymous sign-in JSON response for project {project_id}: {e}")
                    return None
            else:
                # Try to extract detailed error message from response
                try:
                    error_data = response.json()
                    error_message = error_data.get("error", {}).get("message", "Unknown error")
                    print(f"{RED}[AUTH]{RESET} Anonymous sign-in failed for project {project_id}: {error_message}")
                    return None
                except ValueError:
                    print(f"{RED}[AUTH]{RESET} Anonymous sign-in failed for project {project_id} (HTTP {response.status_code})")
                    return None

        except requests.exceptions.RequestException as e:
            print(f"{RED}[AUTH]{RESET} Network error during anonymous sign-in for project {project_id}: {e}")
            return None

    def decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode a JWT token and extract the payload.
        
        Args:
            token: The JWT token string
            
        Returns:
            Decoded JWT payload as dictionary, None if decoding fails

        """
        try:
            # Split the JWT into parts
            parts = token.split(".")
            if len(parts) != 3:
                print(f"{RED}[AUTH]{RESET} Invalid JWT format: expected 3 parts, got {len(parts)}")
                return None

            # Decode the payload (second part)
            payload = parts[1]

            # Add padding if needed (JWT base64 doesn't always include padding)
            missing_padding = len(payload) % 4
            if missing_padding:
                payload += "=" * (4 - missing_padding)

            # Decode base64
            decoded_bytes = base64.urlsafe_b64decode(payload)
            payload_data = json.loads(decoded_bytes.decode("utf-8"))

            return payload_data

        except Exception as e:
            print(f"{RED}[AUTH]{RESET} Failed to decode JWT: {e}")
            return None

    def validate_jwt_aud(self, token: str, expected_project_ids: List[str]) -> Optional[str]:
        """Validate JWT aud field against expected project IDs.
        
        Args:
            token: The JWT token
            expected_project_ids: List of project IDs to validate against
            
        Returns:
            The project ID that matches the aud, None if no match

        """
        payload = self.decode_jwt(token)
        if not payload:
            return None

        aud = payload.get("aud")
        if not aud:
            print(f"{YELLOW}[AUTH]{RESET} JWT does not contain 'aud' field")
            return None

        # Check if aud matches any of the expected project IDs
        for project_id in expected_project_ids:
            if aud == project_id:
                return project_id

        print(f"{YELLOW}[AUTH]{RESET} JWT aud '{aud}' does not match any expected project IDs: {expected_project_ids}")
        return None

    def create_account_with_multiple_keys(
        self,
        project_id: str,
        api_keys: List[str],
        email: str,
        password: str,
        expected_project_ids: List[str],
        package_name: Optional[str] = None,
        cert_sha1_list: Optional[List[str]] = None,
        app_id: Optional[str] = None,
        output_dir: Optional[str] = None
    ) -> Optional[Tuple[str, str]]:
        """Try to create account with multiple API keys and SHA-1 certificates, validate JWT aud.
        
        Args:
            project_id: Firebase project ID for account creation
            api_keys: List of API keys to try
            email: Email address for account creation
            password: Password for account creation
            expected_project_ids: List of project IDs to validate JWT aud against
            package_name: Android package name for X-Android-Package header
            cert_sha1_list: List of Android certificate SHA-1 hashes to try
            app_id: Google App ID for the project
            output_dir: Directory to save successful authentication data to
            
        Returns:
            Tuple of (id_token, validated_project_id) if successful, None if failed

        """
        # Prepare list of SHA-1 certificates to try (None is also valid for no certificate)
        certificates_to_try = cert_sha1_list or [None]

        # Track if we found any valid certificates across all API keys
        any_valid_certificate_found = False

        print("=" * 80)
        for i, api_key in enumerate(api_keys):
            print(f"{BLUE}[AUTH]{RESET} Trying API key {i+1}/{len(api_keys)} for project: {project_id}")

            # Track if we found a valid certificate (passed Android restriction)
            found_valid_certificate = False

            # Try each certificate with this API key
            for cert_index, cert_sha1 in enumerate(certificates_to_try):
                if cert_sha1:
                    print(f"{BLUE}[AUTH]{RESET} Using certificate {cert_index+1}/{len(certificates_to_try)}: {cert_sha1[:8]}...")

                # Clear any previous failure for this project to allow retry with new certificate
                if project_id in self._auth_failures:
                    del self._auth_failures[project_id]

                token = self.create_account_and_get_token(project_id, api_key, email, password, package_name, cert_sha1)
                if token:
                    # Validate JWT aud against expected project IDs
                    validated_project_id = self.validate_jwt_aud(token, expected_project_ids)
                    if validated_project_id:
                        self._jwt_project_mapping[project_id] = validated_project_id
                        if cert_sha1:
                            print(f"{GREEN}[AUTH]{RESET} Success with certificate {cert_sha1[:8]}...")

                        # Save successful authentication data for future resume
                        if output_dir:
                            AuthDataHandler.save_auth_data(
                                project_id=validated_project_id,
                                api_key=api_key,
                                package_name=package_name,
                                cert_sha1=cert_sha1,
                                app_id=app_id,
                                output_dir=output_dir
                            )

                        return token, validated_project_id
                    print(f"{YELLOW}[AUTH]{RESET} JWT aud validation failed for project {project_id}")
                    # Remove the token since aud validation failed
                    if project_id in self._auth_tokens:
                        del self._auth_tokens[project_id]
                else:
                    # Check if the failure was due to Android restriction - only continue for this specific error
                    failure_reason = self._auth_failures.get(project_id, "")
                    if "RESTRICTED TO ANDROID APP" in failure_reason and cert_index < len(certificates_to_try) - 1:
                        print(f"{YELLOW}[AUTH]{RESET} Android restriction detected, trying next certificate...")
                        continue  # Try next certificate
                    if "OPERATION_NOT_ALLOWED" in failure_reason:
                        # This means certificate worked but email/password auth is disabled
                        found_valid_certificate = True
                        any_valid_certificate_found = True
                        if cert_sha1:
                            print(f"{YELLOW}[AUTH]{RESET} Certificate {cert_sha1[:8]}... is valid, but email/password authentication is disabled for this project")
                        else:
                            print(f"{YELLOW}[AUTH]{RESET} Email/password authentication is disabled for this project")
                        break  # Stop trying certificates - we found a working certificate
                    break  # Stop trying certificates for this API key

            if not found_valid_certificate:
                print(f"{YELLOW}[AUTH]{RESET} All certificates failed for API key {i+1}")

        if not any_valid_certificate_found:
            print(f"{RED}[AUTH]{RESET} All API keys and certificates failed for project {project_id}")
        return None

    def get_auth_token(self, project_id: str) -> Optional[str]:
        """Get authentication token for a project.

        Only returns tokens for projects where JWT aud validation succeeded.

        Args:
            project_id: Firebase project ID

        Returns:
            ID token if available and JWT aud validation passed, None otherwise

        """
        # Check if we have a token for this project
        token = self._auth_tokens.get(project_id)
        if not token:
            return None

        # Check if JWT aud validation succeeded for this project
        # If we have JWT validation results, only return token for validated projects
        if self._jwt_project_mapping:
            if project_id not in self._jwt_project_mapping:
                # JWT validation was performed but this project didn't pass validation
                return None

        return token


    def get_auth_summary(self) -> Dict[str, int]:
        """Get summary of authentication attempts.

        Returns:
            Dictionary with success and failure counts

        """
        return {
            "successful_auths": len(self._auth_tokens),
            "failed_auths": len(self._auth_failures),
            "total_projects": len(self._auth_tokens) + len(self._auth_failures)
        }
