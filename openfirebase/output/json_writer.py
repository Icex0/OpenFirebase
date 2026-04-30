"""Build a schema-conformant scan document from in-memory scan results.

See docs/schema/openfirebase-scan.schema.json for the authoritative schema.
This module is a pure transform: it takes whatever the orchestrator already has
(extraction results, per-service scan_results dicts, auth_results) and produces
a JSON-ready dict. No I/O side effects beyond the writer entry point.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .verdict import derive_auth_verdict, derive_unauth_verdict

SCHEMA_VERSION = "2.0"

# Categories that live exclusively on the bundle (paired credentials, signing
# metadata, identifiers). The orchestrator's per-project `extracted_items`
# pivot uses this set to filter — these never appear as parallel string
# arrays per project; they live only in the structured bundle fields.
STRUCTURED_BUNDLE_CATEGORIES = frozenset({
    "Service_Account_Email",
    "Service_Account_Project_ID",
    "Service_Account_Private_Key",
    "Hardcoded_Private_Key",
    "APK_Certificate_SHA1",
    "APK_Package_Name",
    "IPA_Bundle_ID",
})

# Maps internal result dict service labels to schema service enum values.
SERVICE_SLUG = {
    "Realtime Database": "rtdb",
    "Realtime Database Write": "rtdb",
    "Storage": "storage",
    "Storage Write": "storage",
    "Remote Config": "remote_config",
    "Firestore": "firestore",
    "Firestore Write": "firestore",
    "Cloud Functions": "cloud_functions",
}

# Probe classification from scan section title. Matches how the orchestrator
# labels result collections in `_perform_scanning_core`.
WRITE_SECTIONS = {"Storage Write", "Realtime Database Write", "Firestore Write"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _service_from_url(url: str) -> Optional[str]:
    if "firestore.googleapis.com" in url:
        return "firestore"
    if "firebasestorage.googleapis.com" in url or "storage.googleapis.com" in url:
        return "storage"
    if "firebaseremoteconfig.googleapis.com" in url:
        return "remote_config"
    if "cloudfunctions.net" in url:
        return "cloud_functions"
    if ".firebaseio.com" in url or ".firebasedatabase.app" in url:
        return "rtdb"
    return None


def _storage_surface(url: str) -> Optional[str]:
    if "firebasestorage.googleapis.com" in url:
        return "Firebase Rules"
    if "storage.googleapis.com" in url:
        return "GCS IAM"
    return None


def _firestore_collection(url: str) -> Optional[str]:
    match = re.search(r"/documents/([^/?#]+)", url)
    return match.group(1) if match else None


def _cf_region_and_name(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse `https://{region}-{project}.cloudfunctions.net/{name}` or source-bucket URLs."""
    parsed = urlparse(url)
    host = parsed.netloc
    if host.endswith(".cloudfunctions.net"):
        prefix = host[: -len(".cloudfunctions.net")]
        region_match = re.match(r"([a-z]+-[a-z]+[0-9]+)-", prefix)
        region = region_match.group(1) if region_match else None
        name = parsed.path.strip("/").split("/")[0] or None
        return region, name
    bucket_match = re.search(r"/b/gcf-(?:v2-)?sources-\d+-([a-z]+-[a-z]+[0-9]+)/", url)
    if bucket_match:
        return bucket_match.group(1), None
    return None, None


def _looks_like_url(key: str) -> bool:
    return key.startswith("http://") or key.startswith("https://")


def _truncate(value: Any, limit: int = 10000) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "...[truncated]"
    return value


class ScanDocumentBuilder:
    """Accumulates one scan run's data into a schema-conformant dict."""

    def __init__(
        self,
        *,
        tool_version: str,
        scan_id: str,
        input_type: str,
        input_source: Optional[str] = None,
        platform: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        auth_identities: Optional[List[Dict[str, str]]] = None,
    ):
        self.doc: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool_version": tool_version,
            "scan_id": scan_id,
            "started_at": _now_iso(),
            "finished_at": None,
            "input": {
                "type": input_type,
                "source": input_source,
                "platform": platform,
            },
            "config": config or {},
            "auth": {
                "used": bool(auth_identities),
                "identities": auth_identities or [],
            },
            "extraction": {"bundles": []},
            "projects": [],
            "summary": {"per_service": {}},
        }
        # project_id -> project block, so multiple scan sections can append.
        self._projects: Dict[str, Dict[str, Any]] = {}
        # project_id -> {category: [values]}. Set in bulk via
        # ``set_extracted_items`` and merged into project blocks at finalize.
        self._extracted_items: Dict[str, Dict[str, List[str]]] = {}

    # ---- extraction ----

    def add_bundle(
        self,
        *,
        bundle_type: str,
        path: str,
        package_name: Optional[str],
        items: List[Tuple[str, str]],
        sha1_signatures: Optional[List[str]] = None,
    ) -> None:
        """Append one APK/IPA's structured fields to extraction.bundles[].

        `items` is the raw List[(pattern_name, value)] the extractor emits.
        Only the categories that need per-bundle attribution or credential
        pairing land here: SAs (paired email/key/project_id), hardcoded PEMs,
        signing certs, package_name, bundle id. Everything else (Firebase
        project IDs, API keys, app IDs, database/storage URLs, etc.) is
        emitted per-project via `projects[].extracted_items` — the canonical
        source for pattern matches.
        """
        service_accounts: List[Dict[str, str]] = []
        leaked_keys: List[Dict[str, str]] = []
        extracted_sha1: List[str] = []
        extracted_package_name: Optional[str] = None
        extracted_bundle_id: Optional[str] = None

        # SA fields arrive as a triple in extractor emission order
        # (Email → Private_Key → Project_ID). Buffer all three and finalize
        # when the *next* email starts or the loop ends — finalizing on
        # private_key would drop the project_id that follows it.
        pending_email: Optional[str] = None
        pending_key: Optional[str] = None
        pending_project: Optional[str] = None

        def _flush_sa() -> None:
            if pending_email and pending_key:
                service_accounts.append({
                    "client_email": pending_email,
                    "project_id": pending_project or _sa_project_from_email(pending_email),
                    "private_key": pending_key,
                })

        for pattern_name, value in items:
            if pattern_name == "Service_Account_Email":
                _flush_sa()
                pending_email = value
                pending_key = None
                pending_project = None
                continue
            if pattern_name == "Service_Account_Private_Key":
                pending_key = value
                continue
            if pattern_name == "Service_Account_Project_ID":
                pending_project = value
                continue
            if pattern_name == "Hardcoded_Private_Key":
                leaked_keys.append({
                    "pem_type": _pem_type(value),
                    "pem": value,
                })
                continue
            if pattern_name == "APK_Certificate_SHA1":
                extracted_sha1.append(value)
                continue
            if pattern_name == "APK_Package_Name":
                extracted_package_name = value
                continue
            if pattern_name == "IPA_Bundle_ID":
                extracted_bundle_id = value
                continue
            # All other pattern items (Firebase_Project_ID, Google_API_Key,
            # etc.) are surfaced per-project via projects[].extracted_items;
            # we don't duplicate them on the bundle.
        _flush_sa()

        resolved_package = package_name or extracted_package_name or extracted_bundle_id
        bundle_block: Dict[str, Any] = {
            "type": bundle_type,
            "path": path,
            "package_name": resolved_package,
            "service_accounts": service_accounts,
            "leaked_private_keys": leaked_keys,
        }
        combined_sha1 = list(sha1_signatures or []) + extracted_sha1
        if combined_sha1:
            bundle_block["signatures"] = {"sha1": combined_sha1}
        self.doc["extraction"].setdefault("bundles", []).append(bundle_block)

    def set_dns(self, matched_project_ids: Iterable[str]) -> None:
        self.doc["extraction"]["dns"] = {
            "matched_project_ids": sorted(set(matched_project_ids)),
        }

    def set_extracted_items(
        self, by_project: Dict[str, Dict[str, List[str]]]
    ) -> None:
        """Stage per-project extracted items: ``{project_id: {category: [values]}}``."""
        self._extracted_items = {
            pid: {cat: list(vals) for cat, vals in cats.items() if vals}
            for pid, cats in by_project.items()
        }

    # ---- findings ----

    def add_scan_section(
        self,
        *,
        section_title: str,
        scan_results: Dict[str, Dict[str, Dict[str, Any]]],
        auth_results: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
        package_names_by_project: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """Ingest one scan section's results.

        scan_results shape: {project_id: {url: {status, security, message, ...}}}
        auth_results shape: same, but keyed by post-retry results from scanner.all_authenticated_results.
        section_title is e.g. "Firestore" / "Firestore Write" / "Cloud Functions".
        """
        probe = "write" if section_title in WRITE_SECTIONS else "read"
        auth_results = auth_results or {}

        for project_id, url_results in scan_results.items():
            project_block = self._project(project_id, package_names_by_project)
            project_auth = auth_results.get(project_id, {})
            for url, result in url_results.items():
                if not _looks_like_url(url):
                    continue
                finding = self._build_finding(
                    url=url,
                    probe=probe,
                    unauth_result=result,
                    auth_result=project_auth.get(url),
                )
                project_block["findings"].append(finding)

    def _build_finding(
        self,
        *,
        url: str,
        probe: str,
        unauth_result: Dict[str, Any],
        auth_result: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        service = _service_from_url(url) or "rtdb"
        status = str(unauth_result.get("status", ""))
        security = str(unauth_result.get("security", "UNKNOWN"))

        finding: Dict[str, Any] = {
            "service": service,
            "url": url,
            "probe": probe,
            "resource": _resource_for(service, url),
            "unauth": {
                "status": status,
                "security": security,
                "message": unauth_result.get("message", ""),
                "response_content": _truncate(unauth_result.get("response_content")),
                "response_content_full": _truncate(
                    unauth_result.get("response_content_full")
                    or unauth_result.get("response_content"),
                    limit=100_000,
                ),
                "verdict": derive_unauth_verdict(service, status, security),
            },
            "auth": None,
            "error": _maybe_error("unauth", security, unauth_result.get("message", "")),
        }

        if auth_result:
            a_status = str(auth_result.get("status", ""))
            a_security = str(auth_result.get("security", "UNKNOWN"))
            identity = _identity_from_auth_security(a_security)
            finding["auth"] = {
                "status": a_status,
                "security": a_security,
                "message": auth_result.get("message", ""),
                "response_content": _truncate(auth_result.get("response_content")),
                "response_content_full": _truncate(
                    auth_result.get("response_content_full")
                    or auth_result.get("response_content"),
                    limit=100_000,
                ),
                "verdict": derive_auth_verdict(service, a_status, a_security),
                "identity": identity,
            }
            if finding["error"] is None:
                finding["error"] = _maybe_error("auth", a_security, auth_result.get("message", ""))

        return finding

    def _project(
        self,
        project_id: str,
        package_names_by_project: Optional[Dict[str, List[str]]],
    ) -> Dict[str, Any]:
        if project_id not in self._projects:
            block = {
                "project_id": project_id,
                "package_names": (
                    list(package_names_by_project.get(project_id, []))
                    if package_names_by_project
                    else []
                ),
                "extracted_items": {},
                "findings": [],
            }
            self._projects[project_id] = block
            self.doc["projects"].append(block)
        return self._projects[project_id]

    # ---- finalize ----

    def finalize(self) -> Dict[str, Any]:
        # Auto-creates project blocks for extraction-only projects (no findings).
        for project_id, items in self._extracted_items.items():
            block = self._project(project_id, package_names_by_project=None)
            block["extracted_items"] = items
        self.doc["finished_at"] = _now_iso()
        self.doc["summary"]["per_service"] = _build_summary(self.doc["projects"])
        return self.doc

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.finalize(), f, indent=2, ensure_ascii=False)


# ------------- helpers -------------

def _resource_for(service: str, url: str) -> Dict[str, Any]:
    resource: Dict[str, Any] = {"origin": "extracted"}
    if service == "firestore":
        collection = _firestore_collection(url)
        if collection:
            resource["collection"] = collection
    elif service == "storage":
        surface = _storage_surface(url)
        if surface:
            resource["surface"] = surface
    elif service == "cloud_functions":
        region, name = _cf_region_and_name(url)
        if region:
            resource["region"] = region
        if name:
            resource["function_name"] = name
    return resource


def _maybe_error(stage: str, security: str, message: str) -> Optional[Dict[str, str]]:
    if security in {"TIMEOUT", "CONNECTION_ERROR", "ERROR"}:
        return {"stage": stage, "kind": security, "message": message or security.lower()}
    return None


def _identity_from_auth_security(security: str) -> Dict[str, str]:
    if security.endswith("_SA") or security == "PUBLIC_SA":
        return {"kind": "service_account", "ref": ""}
    return {"kind": "user_token", "ref": ""}


def _pem_type(pem: str) -> str:
    match = re.search(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----", pem)
    return match.group(1) if match else "PRIVATE KEY"


def _sa_project_from_email(email: Optional[str]) -> str:
    if not email:
        return ""
    # Formats: foo@PROJECT.iam.gserviceaccount.com, foo@appspot.gserviceaccount.com
    match = re.search(r"@([a-z0-9-]+)\.iam\.gserviceaccount\.com", email)
    if match:
        return match.group(1)
    match = re.search(r"@([a-z0-9-]+)\.gserviceaccount\.com", email)
    if match:
        return match.group(1)
    return ""


def _build_summary(projects: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    per_service: Dict[str, Dict[str, int]] = {}
    for project in projects:
        for finding in project.get("findings", []):
            service = finding["service"]
            bucket = per_service.setdefault(service, {
                "read_public_unauth": 0,
                "read_public_auth": 0,
                "write_public_unauth": 0,
                "write_public_auth": 0,
                "app_check": 0,
                "protected": 0,
                "not_found": 0,
                "rate_limited": 0,
                "errors": 0,
                "other": 0,
            })
            probe = finding["probe"]
            u_verdict = finding["unauth"]["verdict"]
            a_verdict = finding["auth"]["verdict"] if finding.get("auth") else None

            if u_verdict == "public":
                bucket[f"{probe}_public_unauth"] += 1
            elif a_verdict == "public":
                bucket[f"{probe}_public_auth"] += 1
            elif a_verdict == "app_check":
                bucket["app_check"] += 1
            elif u_verdict == "protected":
                bucket["protected"] += 1
            elif u_verdict == "not_found":
                bucket["not_found"] += 1
            elif u_verdict == "rate_limited":
                bucket["rate_limited"] += 1
            elif u_verdict == "error":
                bucket["errors"] += 1
            else:
                bucket["other"] += 1
    return per_service
