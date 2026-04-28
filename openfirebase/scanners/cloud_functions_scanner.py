"""Cloud Functions Scanner for OpenFirebase

Handles Firebase Cloud Functions scanning functionality.
Probes extracted and enumerated function endpoints for accessibility.
"""

import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from ..core.config import BLUE, CLOUD_FUNCTIONS_REGIONS, LIME, ORANGE, RED, RESET, YELLOW
from ..utils import is_shutdown_requested
from .base import BaseScanner

# Default wordlist path (relative to this file)
DEFAULT_WORDLIST_PATH = Path(__file__).parent.parent / "wordlist" / "cloud-functions-top-250.txt"

# Build a set of known regions for URL parsing
_CF_REGION_SET = frozenset(CLOUD_FUNCTIONS_REGIONS)


def _extract_project_id_from_cf_url(url: str) -> Optional[str]:
    """Extract project ID from a Cloud Functions URL.

    The hostname format is {region}-{project_id}.cloudfunctions.net.
    Since both regions and project IDs can contain hyphens, we match
    against the known region list to split correctly.
    """
    match = re.match(r"(?:https?://)?([^/]+)\.cloudfunctions\.net", url)
    if not match:
        return None
    prefix = match.group(1)  # e.g. "us-central1-openfirebase-test"

    # Try each known region as a prefix
    for region in _CF_REGION_SET:
        if prefix.startswith(region + "-"):
            return prefix[len(region) + 1:]

    return None


class CloudFunctionsScanner(BaseScanner):
    """Scans Firebase Cloud Functions for accessibility and security status."""

    resource_type = "cloud_functions"
    display_name = "FIREBASE CLOUD FUNCTIONS"
    resource_word = "cloud functions"

    def _get_status_message(self, status, security, message, result, colorize=True):
        """Cloud Functions-specific status messages."""
        from ..core.config import (
            STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK,
            STATUS_TOO_MANY_REQUESTS, STATUS_UNAUTHORIZED,
        )
        if colorize:
            from ..core.config import RED, LIME, YELLOW, GREY, RESET
        else:
            RED = LIME = YELLOW = GREY = RESET = ""

        if security == "SKIPPED":
            return f"{GREY}[-]{RESET} SKIPPED - {message}"
        if security == "SOURCE_LEAK":
            return f"{LIME}[+]{RESET} SOURCE CODE LEAK - Cloud Functions source code bucket is publicly listable!"
        if security == "PUBLIC" or status == STATUS_OK:
            return f"{LIME}[+]{RESET} PUBLIC FUNCTION - This Cloud Function is publicly accessible!"
        if status in [STATUS_UNAUTHORIZED, STATUS_FORBIDDEN]:
            return f"{RED}[-]{RESET} PROTECTED - Cloud Function requires authentication"
        if status == STATUS_NOT_FOUND:
            return f"{RED}[-]{RESET} NOT FOUND - Cloud Function not found"
        if status == STATUS_TOO_MANY_REQUESTS:
            return f"{YELLOW}[!]{RESET}  RATE LIMITED - {message}"
        return f"{GREY}[UNK]{RESET} UNKNOWN - {message}"

    def _is_result_public(self, status, security):
        """Cloud Functions: 400/405/500 with security=PUBLIC are also public."""
        from ..core.config import STATUS_OK
        return security in ["PUBLIC", "SOURCE_LEAK"] or status == STATUS_OK

    def _get_summary_labels(self):
        return {
            "public": "Public/reachable cloud functions found (200/400/405/415/500)",
            "protected": "Protected cloud functions (401/403)",
            "not_found": "Cloud functions not found (404)",
            "rate_limited": "Rate limited (429)",
            "other": "Other/errors",
        }

    def scan_project_id(self, project_id: str) -> Dict[str, str]:
        """Scan a single project ID — not used directly for Cloud Functions.

        Cloud Functions scanning is driven by scan_cloud_functions() instead,
        which handles URLs, callables, and enumeration.
        """
        return {}

    def scan_project_ids(self, project_ids: Set[str], **kwargs) -> Dict[str, Dict[str, str]]:
        """Scan multiple project IDs — delegates to scan_cloud_functions()."""
        return self.scan_cloud_functions(project_ids, **kwargs)

    def _extract_project_id_from_url(self, url: str) -> Optional[str]:
        """Extract Firebase project ID from a Cloud Functions URL.

        Handles URLs like:
            https://us-central1-myproject.cloudfunctions.net/funcName
            https://europe-west1-myproject.cloudfunctions.net/funcName
        """
        result = _extract_project_id_from_cf_url(url)
        if result:
            return result

        # Fall back to parent implementation for other URL types
        return super()._extract_project_id_from_url(url)

    @staticmethod
    def _extract_base_function_url(url: str) -> str:
        """Extract the base function URL without subroutes or query params.

        IAM applies at the function level, not per-path, so auth probes
        only need the base URL.

        Example:
            https://us-central1-proj.cloudfunctions.net/api/users?q=1
            -> https://us-central1-proj.cloudfunctions.net/api
        """
        parsed = urlparse(url)
        # Path is like /api/users/endpoint — take only the first segment
        path_parts = parsed.path.strip("/").split("/")
        base_path = f"/{path_parts[0]}" if path_parts and path_parts[0] else "/"
        return f"{parsed.scheme}://{parsed.netloc}{base_path}"

    @staticmethod
    def _extract_function_name(url: str) -> str:
        """Extract the function name from a Cloud Functions URL."""
        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")
        return path_parts[0] if path_parts and path_parts[0] else ""

    @staticmethod
    def _build_function_url(project_id: str, region: str, function_name: str) -> str:
        """Build a Cloud Functions URL from components."""
        return f"https://{region}-{project_id}.cloudfunctions.net/{function_name}"

    @staticmethod
    def extract_project_number(google_app_id: str) -> Optional[str]:
        """Extract GCP project number from Google App ID.

        Format: 1:{project_number}:android:{hash} or 1:{project_number}:ios:{hash}
        """
        match = re.match(r"1:(\d+):[a-z]+:[a-f0-9]+", google_app_id)
        return match.group(1) if match else None

    # -------------------------------------------------------------------------
    # HTTP function probing
    # -------------------------------------------------------------------------

    @staticmethod
    def _is_gcp_not_found(response) -> bool:
        """Distinguish a real GCP 'function not found' 404 from a 404 the
        function itself returned (e.g. Express 'Cannot GET /').

        GCP's front door returns an HTML body with <title>404 Page not found</title>
        when no function is deployed at that URL. Anything else at status 404
        means the function exists but returned 404 from its own handler.
        """
        if response.status_code != 404:
            return False
        body = response.text or ""
        return "<title>404 Page not found</title>" in body

    def _test_http_function(self, url: str) -> Dict[str, str]:
        """Test an HTTP trigger Cloud Function for accessibility.

        Sends GET and POST requests to determine auth state.
        """
        try:
            response = self.session.get(url, timeout=self.timeout)

            # If GET returns 405 (method not allowed) or 415 (unsupported
            # content type — function expects a JSON body), retry with POST.
            if response.status_code in (405, 415):
                response = self.session.post(
                    url,
                    json={},
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                )

            # Handle common status codes with auth retry
            common_result = self._handle_common_status_codes_with_auth(
                response, url, "GET"
            )
            if common_result:
                return common_result

            if response.status_code == 404:
                if self._is_gcp_not_found(response):
                    return self._build_response_dict(
                        404, "Function not found", False, "NOT_FOUND"
                    )
                # 404 from the function's own handler — function exists
                return self._build_response_dict(
                    404,
                    "Public access (function exists, handler returned 404)",
                    True,
                    "PUBLIC",
                    response.text,
                )

            # 400/405/500 etc. means the function exists and is reachable
            # (it just needs different parameters or had an error)
            if response.status_code in (400, 405, 415, 500):
                return self._build_response_dict(
                    response.status_code,
                    "Public access (function exists, returned error — missing parameters or internal error)",
                    True,
                    "PUBLIC",
                    response.text,
                )

            return self._build_response_dict(
                response.status_code,
                f"HTTP {response.status_code}",
                False,
                "UNKNOWN",
                response.text,
            )

        except requests.exceptions.Timeout:
            return self._build_response_dict(
                0, "Request timeout", False, "TIMEOUT"
            )
        except requests.exceptions.ConnectionError:
            return self._build_response_dict(
                0, "Connection error", False, "CONNECTION_ERROR"
            )
        except requests.exceptions.RequestException as e:
            return self._build_response_dict(
                0, f"Request failed: {e!s}", False, "ERROR"
            )

    # -------------------------------------------------------------------------
    # Callable function probing
    # -------------------------------------------------------------------------

    def _test_callable_function(self, url: str) -> Dict[str, str]:
        """Test a callable Cloud Function using the Firebase callable protocol.

        POST with {"data": {}} and Content-Type: application/json.
        """
        try:
            response = self.session.post(
                url,
                json={"data": {}},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )

            # Handle common status codes with auth retry
            common_result = self._handle_common_status_codes_with_auth(
                response, url, "POST", json={"data": {}},
                headers={"Content-Type": "application/json"},
            )
            if common_result:
                return common_result

            if response.status_code == 404:
                if self._is_gcp_not_found(response):
                    return self._build_response_dict(
                        404, "Callable function not found", False, "NOT_FOUND"
                    )
                # 404 from the function's own handler — function exists
                return self._build_response_dict(
                    404,
                    "Public access (callable exists, handler returned 404)",
                    True,
                    "PUBLIC",
                    response.text,
                )

            if response.status_code in (400, 405, 415, 500):
                return self._build_response_dict(
                    response.status_code,
                    "Public access (callable exists, returned error — missing parameters or internal error)",
                    True,
                    "PUBLIC",
                    response.text,
                )

            return self._build_response_dict(
                response.status_code,
                f"HTTP {response.status_code}",
                False,
                "UNKNOWN",
                response.text,
            )

        except requests.exceptions.Timeout:
            return self._build_response_dict(
                0, "Request timeout", False, "TIMEOUT"
            )
        except requests.exceptions.ConnectionError:
            return self._build_response_dict(
                0, "Connection error", False, "CONNECTION_ERROR"
            )
        except requests.exceptions.RequestException as e:
            return self._build_response_dict(
                0, f"Request failed: {e!s}", False, "ERROR"
            )

    # -------------------------------------------------------------------------
    # GCS source bucket probing (liveness + source code leak detection)
    # -------------------------------------------------------------------------

    def probe_gcf_source_buckets(
        self, project_number: str, regions: List[str] = None,
    ) -> Dict[str, Dict[str, str]]:
        """Probe GCS source code buckets for Cloud Functions.

        Checks both Gen 1 (gcf-sources-*) and Gen 2 (gcf-v2-sources-*) buckets.

        Returns:
            Dict mapping region -> {gen1_status, gen2_status, alive, source_leak}
        """
        if regions is None:
            regions = CLOUD_FUNCTIONS_REGIONS

        results = {}

        for region in regions:
            if is_shutdown_requested():
                break

            region_result = {
                "gen1_status": None,
                "gen2_status": None,
                "alive": False,
                "source_leak": False,
                "source_leak_urls": [],
            }

            for gen, prefix in [("gen1", "gcf-sources"), ("gen2", "gcf-v2-sources")]:
                bucket_name = f"{prefix}-{project_number}-{region}"
                api_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"

                try:
                    response = self.session.get(api_url, timeout=self.timeout)
                    status = response.status_code

                    region_result[f"{gen}_status"] = status

                    if status == 200:
                        # Source code is publicly listable — critical finding
                        region_result["alive"] = True
                        region_result["source_leak"] = True
                        # Try to extract object names
                        try:
                            data = response.json()
                            for item in data.get("items", []):
                                region_result["source_leak_urls"].append(
                                    f"gs://{bucket_name}/{item.get('name', '')}"
                                )
                        except (ValueError, KeyError):
                            pass
                    elif status in (401, 403):
                        # Bucket exists but access denied — functions deployed here
                        region_result["alive"] = True

                except requests.exceptions.RequestException:
                    region_result[f"{gen}_status"] = 0

                time.sleep(1.0 / self.rate_limit)

            results[region] = region_result

        return results

    # -------------------------------------------------------------------------
    # Scan extracted URLs
    # -------------------------------------------------------------------------

    def scan_extracted_urls(
        self, urls: Set[str],
    ) -> Dict[str, Dict[str, str]]:
        """Probe every extracted HTTP trigger URL individually.

        IAM invoke permissions (allUsers/allAuthenticatedUsers) apply at
        the function level — path-level IAM conditions only work for
        specific principals, not public access.  We still probe each URL
        individually because application-layer routing (e.g. Express)
        can return different responses per path, and the user should see
        every extracted URL with its actual response.
        """
        results = {}

        for url in sorted(urls):
            if is_shutdown_requested():
                break

            result = self._test_http_function(url)
            results[url] = result

            # Print result immediately
            self._print_single_result(url, result)

            time.sleep(1.0 / self.rate_limit)

        return results

    # -------------------------------------------------------------------------
    # Scan callable functions
    # -------------------------------------------------------------------------

    def scan_callables(
        self,
        project_id: str,
        callable_names: Set[str],
        regions: Set[str],
    ) -> Dict[str, Dict[str, str]]:
        """Reconstruct and probe callable function URLs.

        Tries each callable name against each region.
        """
        results = {}

        # explicit_regions = user-specified via --function-region (always probed)
        # us-central1 added as fallback unless already explicit.
        # Preserve CLOUD_FUNCTIONS_REGIONS tier order for explicit regions,
        # falling back to alphabetical for any unknown regions.
        explicit_regions = set(regions)
        ordered_explicit = [r for r in CLOUD_FUNCTIONS_REGIONS if r in explicit_regions]
        ordered_explicit += sorted(r for r in explicit_regions if r not in set(CLOUD_FUNCTIONS_REGIONS))
        if "us-central1" not in explicit_regions:
            region_order = ["us-central1"] + [r for r in ordered_explicit if r != "us-central1"]
        else:
            region_order = ordered_explicit

        for name in sorted(callable_names):
            if is_shutdown_requested():
                break

            for region in region_order:
                url = self._build_function_url(project_id, region, name)
                is_explicit = region in explicit_regions

                result = self._test_callable_function(url)

                # For the us-central1 fallback, skip 404s silently
                if result.get("security") == "NOT_FOUND" and not is_explicit:
                    time.sleep(1.0 / self.rate_limit)
                    continue

                results[url] = result
                self._print_single_result(url, result, callable=True)
                time.sleep(1.0 / self.rate_limit)

            time.sleep(1.0 / self.rate_limit)

        return results

    # -------------------------------------------------------------------------
    # Function enumeration (--fuzz-functions)
    # -------------------------------------------------------------------------

    def enumerate_functions(
        self,
        project_id: str,
        wordlist: List[str],
        alive_regions: List[str],
        known_functions: Set[str] = None,
    ) -> Dict[str, Dict[str, str]]:
        """Brute-force function names from wordlist in alive regions.

        Only enumerates in regions where GCS bucket probes returned 401/200.
        """
        results = {}
        known = known_functions or set()

        total = len(wordlist) * len(alive_regions)
        tested = 0

        for region in alive_regions:
            if is_shutdown_requested():
                break

            for name in wordlist:
                if is_shutdown_requested():
                    break

                # Skip functions we already know about
                if name in known:
                    tested += 1
                    continue

                tested += 1
                if tested % 20 == 0:
                    print(
                        f"   Fuzzing progress: {tested}/{total} functions tested..."
                    )

                url = self._build_function_url(project_id, region, name)
                try:
                    response = self.session.get(url, timeout=self.timeout)
                except requests.exceptions.RequestException:
                    time.sleep(1.0 / self.rate_limit)
                    continue

                # Only real GCP 'function not found' 404s are skipped silently.
                # A 404 from the function's own handler means it exists.
                if response.status_code == 404 and self._is_gcp_not_found(response):
                    time.sleep(1.0 / self.rate_limit)
                    continue

                # Anything else is a hit
                common_result = self._handle_common_status_codes_with_auth(
                    response, url, "GET"
                )
                if common_result:
                    result = common_result
                elif response.status_code in (400, 404, 405, 415, 500):
                    result = self._build_response_dict(
                        response.status_code,
                        "Public access (function exists, returned error — missing parameters or internal error)",
                        True,
                        "PUBLIC",
                        response.text,
                    )
                else:
                    result = self._build_response_dict(
                        response.status_code,
                        f"HTTP {response.status_code}",
                        False,
                        "UNKNOWN",
                        response.text,
                    )

                results[url] = result
                print(f"   {LIME}[+]{RESET} Found function: {name} ({region})")

                time.sleep(1.0 / self.rate_limit)

        return results

    # -------------------------------------------------------------------------
    # Main scan entry point
    # -------------------------------------------------------------------------

    def scan_cloud_functions(
        self,
        project_ids: Set[str],
        extracted_urls: Set[str] = None,
        callable_names: Set[str] = None,
        extracted_regions: Set[str] = None,
        package_project_ids: Dict[str, Set[str]] = None,
        output_file: str = None,
        create_open_only: bool = True,
        fuzz: bool = False,
        fuzz_wordlist_path: str = None,
        google_app_ids: Set[str] = None,
        app_ids_by_project: Dict[str, Set[str]] = None,
        callable_names_by_project: Dict[str, Set[str]] = None,
    ) -> Dict[str, Dict[str, Dict[str, str]]]:
        """Scan Cloud Functions for multiple project IDs.

        Returns:
            Dict[project_id] -> Dict[url] -> result_dict
        """
        all_results = {}

        # Create reverse mapping from project ID to package names
        project_to_packages = {}
        if package_project_ids:
            for package_name, project_id_set in package_project_ids.items():
                for project_id in project_id_set:
                    if project_id not in project_to_packages:
                        project_to_packages[project_id] = []
                    project_to_packages[project_id].append(package_name)

        # Initialize output file
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("Firebase Cloud Functions Read Results\n")
                f.write("=" * 80 + "\n\n")

        # Load wordlist for fuzzing if requested
        fuzz_wordlist = []
        if fuzz:
            wl_path = fuzz_wordlist_path or str(DEFAULT_WORDLIST_PATH)
            try:
                with open(wl_path, encoding="utf-8") as f:
                    fuzz_wordlist = [
                        line.strip() for line in f if line.strip() and not line.startswith("#")
                    ]
                print(
                    f"{BLUE}[INF]{RESET} Loaded {len(fuzz_wordlist)} function names from wordlist\n"
                )
            except OSError as e:
                print(f"{RED}[ERR]{RESET} Failed to load wordlist: {e}")

        # Build per-project map of project_id -> project_number.
        # Fall back to any Google App ID in project-ID mode where we have only one project.
        project_number_by_project: Dict[str, str] = {}
        if app_ids_by_project:
            for pid, app_ids in app_ids_by_project.items():
                for app_id in app_ids:
                    pn = self.extract_project_number(app_id)
                    if pn:
                        project_number_by_project[pid] = pn
                        break

        # Group extracted URLs by project ID
        urls_by_project: Dict[str, Set[str]] = {}
        if extracted_urls:
            for url in extracted_urls:
                # Normalize: extracted URLs may be stored without a scheme
                normalized = url if url.startswith(("http://", "https://")) else f"https://{url}"
                pid = self._extract_project_id_from_url(normalized)
                if pid:
                    urls_by_project.setdefault(pid, set()).add(normalized)

        # Ensure all project IDs from URLs are included
        all_project_ids = set(project_ids)
        all_project_ids.update(urls_by_project.keys())

        regions = extracted_regions or set()

        # Iterate project IDs in package order: all projects from package A,
        # then package B, etc. Any project IDs not tied to a package go last.
        ordered_project_ids = []
        seen = set()
        if package_project_ids:
            for package_name, project_id_set in package_project_ids.items():
                for pid in sorted(project_id_set):
                    if pid in all_project_ids and pid not in seen:
                        ordered_project_ids.append(pid)
                        seen.add(pid)
        for pid in sorted(all_project_ids):
            if pid not in seen:
                ordered_project_ids.append(pid)
                seen.add(pid)

        for project_id in ordered_project_ids:
            if is_shutdown_requested():
                print(f"\n{RED}[X]{RESET} Shutdown requested. Stopping...")
                break

            package_names = project_to_packages.get(project_id, [])
            self._print_project_header(project_id, package_names)

            project_results = {}
            known_function_names = set()

            # Phase 0: GCS bucket liveness probe (if project number available)
            # This tells us whether the project has any Cloud Functions at all,
            # and in which regions, so we can avoid probing dead projects/regions.
            alive_regions = None  # None = unknown (no project number); [] = known-empty
            project_urls = urls_by_project.get(project_id, set())

            project_number = project_number_by_project.get(project_id)
            if project_number:
                print(
                    f"{BLUE}[INF]{RESET} Probing GCS source buckets across {len(CLOUD_FUNCTIONS_REGIONS)} regions "
                    f"(project number: {project_number})..."
                )
                bucket_results = self.probe_gcf_source_buckets(project_number)

                alive_regions = []
                for region, info in bucket_results.items():
                    if info["source_leak"]:
                        print(
                            f"   {LIME}[+]{RESET} {RED}SOURCE CODE LEAK{RESET} in {region}! "
                            f"Bucket is publicly listable"
                        )
                        for gs_url in info.get("source_leak_urls", [])[:5]:
                            print(f"      {gs_url}")

                        for gen in ("gen1", "gen2"):
                            prefix = "gcf-sources" if gen == "gen1" else "gcf-v2-sources"
                            if info.get(f"{gen}_status") == 200:
                                bucket_name = f"{prefix}-{project_number}-{region}"
                                leak_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
                                project_results[leak_url] = self._build_response_dict(
                                    200,
                                    f"Cloud Functions source code bucket is publicly listable ({gen})",
                                    True,
                                    "SOURCE_LEAK",
                                )

                    if info["alive"]:
                        alive_regions.append(region)

                if alive_regions:
                    print(
                        f"{BLUE}[INF]{RESET} Cloud Functions detected in {len(alive_regions)} region(s): "
                        f"{', '.join(alive_regions)}"
                    )
                else:
                    print(
                        f"{YELLOW}[!]{RESET}  No Cloud Functions source buckets found in any region — "
                        f"skipping function probes for this project\n"
                    )

            # If GCS probe confirmed no Cloud Functions exist, skip all probing.
            # Keep any source-leak findings already added.
            skip_probes = alive_regions is not None and len(alive_regions) == 0

            if skip_probes:
                project_results["(no Cloud Functions source buckets found — probes skipped)"] = {
                    "status": "skipped",
                    "security": "SKIPPED",
                    "message": "No GCS source buckets found in any region",
                }

            # Phase 1a: Probe extracted HTTP trigger URLs
            if project_urls and not skip_probes:
                print(
                    f"{BLUE}[INF]{RESET} Testing {len(project_urls)} extracted HTTP function URL(s)..."
                )
                url_results = self.scan_extracted_urls(project_urls)
                project_results.update(url_results)

                for url in url_results:
                    name = self._extract_function_name(url)
                    if name:
                        known_function_names.add(name)

            # Phase 1b: Probe callable functions — constrain to alive_regions when known
            # Use per-project callable names when available (from extraction) so we
            # don't test callables from other APKs against this project.
            if callable_names_by_project and project_id in callable_names_by_project:
                project_callable_names = callable_names_by_project[project_id]
            elif package_names:
                # Project is tied to packages but none contributed callable names —
                # don't fall back to the global set (those belong to other packages).
                project_callable_names = set()
            else:
                project_callable_names = callable_names

            if project_callable_names and not skip_probes:
                callable_regions = set(alive_regions) if alive_regions else regions
                print(
                    f"{BLUE}[INF]{RESET} Testing {len(project_callable_names)} callable function(s)...\n"
                )
                callable_results = self.scan_callables(
                    project_id, project_callable_names, callable_regions
                )
                project_results.update(callable_results)

                for url in callable_results:
                    name = self._extract_function_name(url)
                    if name:
                        known_function_names.add(name)

            # Phase 2: fuzz enumeration
            if fuzz and fuzz_wordlist and not skip_probes:
                if alive_regions is None:
                    # No project number — fall back to extracted regions + us-central1
                    print(
                        f"{YELLOW}[!]{RESET}  No Google App ID available for GCS bucket probing, "
                        f"using extracted regions only or falling back to the default region us-central1"
                    )
                    fuzz_regions = list(regions) if regions else ["us-central1"]
                else:
                    fuzz_regions = alive_regions

                if fuzz_regions:
                    print(
                        f"{BLUE}[INF]{RESET} Fuzzing {len(fuzz_wordlist)} function names "
                        f"across {len(fuzz_regions)} region(s)..."
                    )
                    enum_results = self.enumerate_functions(
                        project_id, fuzz_wordlist, fuzz_regions, known_function_names
                    )
                    project_results.update(enum_results)

                    print(f"{BLUE}[INF]{RESET} Fuzzing completed for project {project_id}:")
                    if enum_results:
                        print(
                            f"   {LIME}[+]{RESET} Found {len(enum_results)} public function(s)"
                        )
                        for enum_url in enum_results:
                            fn_name = enum_url.rstrip("/").rsplit("/", 1)[-1]
                            host = enum_url.split("//", 1)[-1].split(".", 1)[0]
                            region = host.rsplit(f"-{project_id}", 1)[0] if f"-{project_id}" in host else host
                            print(f"      - {fn_name} ({region})")
                    else:
                        print(f"   {YELLOW}[!]{RESET} No additional public functions found")
                    print()

            # Display authenticated results
            self._display_verbose_authenticated_results(project_results)

            # Store authenticated results for this project
            if self.authenticated_results:
                self.all_authenticated_results[project_id] = self.authenticated_results.copy()
            self.authenticated_results.clear()

            # If no results at all, explain why so the output isn't an empty block
            if not project_results:
                if not project_number and not project_urls:
                    reason = "No extracted function URLs and no project number for GCS probing"
                elif alive_regions and not project_urls:
                    reason = (
                        f"GCS source buckets found in {', '.join(alive_regions)} but no extracted "
                        f"function URLs or callable names — use --fuzz-functions to enumerate"
                    )
                else:
                    reason = "No function URLs, callable names, or wordlist to probe"
                print(
                    f"{YELLOW}[!]{RESET}  {reason}\n"
                )
                project_results["(skipped — " + reason + ")"] = {
                    "status": "skipped",
                    "security": "SKIPPED",
                    "message": reason,
                }

            all_results[project_id] = project_results

            # Save to file
            if output_file:
                self._save_project_results_to_file(
                    project_id, project_results, output_file, package_names
                )
                if project_id in self.all_authenticated_results:
                    self._save_authenticated_results_to_file_for_project(
                        project_id, output_file
                    )

        # Save final summary
        if output_file:
            self._save_final_summary_to_file(all_results, output_file)
            if create_open_only:
                self._save_open_only_results(
                    all_results, output_file, package_project_ids
                )

        return all_results

    # -------------------------------------------------------------------------
    # Console output helpers
    # -------------------------------------------------------------------------

    def _print_single_result(
        self, url: str, result: Dict[str, str], callable: bool = False
    ):
        """Print a single function result immediately."""
        status = result.get("status", "unknown")
        security = result.get("security", "unknown")
        message = result.get("message", "No message")

        suffix = " (Callable)" if callable else ""
        print(f"URL: {url}{suffix}")
        print(f"Status: {status}")
        print(f"Response: {message}")

        if "response_content" in result:
            print(f"Content: {result['response_content']}")

        status_message = self._get_status_message(
            status, security, message, result
        )
        print(f"\n{status_message}\n")

    def _print_project_header(self, project_id: str, package_names: List[str] = None):
        """Print project header before testing functions."""
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

    # -------------------------------------------------------------------------
    # File output helpers
    # -------------------------------------------------------------------------

    def _save_project_results_to_file(
        self,
        project_id: str,
        results: Dict[str, Dict[str, str]],
        output_file: str,
        package_names: List[str] = None,
    ):
        """Save individual project results to file."""
        with open(output_file, "a", encoding="utf-8") as f:
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
                status = result.get("status", "unknown")
                security = result.get("security", "unknown")
                message = result.get("message", "No message")

                f.write(f"URL: {url}\n")
                f.write(f"Status: {status}\n")
                f.write(f"Response: {message}\n")

                if "response_content" in result:
                    f.write(f"Content: {result['response_content']}\n")

                status_message = self._get_status_message(
                    status, security, message, result,
                    colorize=False,
                )
                f.write(f"{status_message}\n")
                f.write("\n")

            f.write("\n")

    def _save_final_summary_to_file(
        self,
        results: Dict[str, Dict[str, Dict[str, str]]],
        output_file: str,
        _resource_type: str = None,
    ):
        """Save final summary to file."""
        with open(output_file, "a", encoding="utf-8") as f:
            counts = self._count_scan_results(results)
            labels = self._get_summary_labels()

            f.write(f"[UNAUTH] SCAN SUMMARY {self.display_name}\n")
            f.write("=" * 80 + "\n")
            f.write(f"Total projects scanned: {counts['total_projects']}\n")
            f.write(f"{labels['public']}: {counts['public_count']}\n")
            f.write(f"{labels['protected']}: {counts['protected_count']}\n")
            if "not_found" in labels:
                f.write(f"{labels['not_found']}: {counts['not_found_count']}\n")
            if counts.get("other_count", 0) > 0:
                f.write(f"{labels['other']}: {counts['other_count']}\n")
