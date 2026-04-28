"""Derive stable verdict buckets from raw (status, security) emitted by scanners.

The `verdict` vocab is what the webapp keys off. It's intentionally small and
service-agnostic so UI logic doesn't churn when scanners add new internal
`security` values. Raw `status` / `security` stay in the JSON doc for forensics.
"""

from __future__ import annotations

TRANSPORT_SECURITY = {"TIMEOUT", "CONNECTION_ERROR", "ERROR"}


def derive_unauth_verdict(service: str, status: str, security: str) -> str:
    """Verdict for an unauthenticated probe result.

    Returns one of: public, protected, not_found, rate_limited, locked, error, unknown.
    """
    if security in TRANSPORT_SECURITY:
        return "error"

    if _is_public_unauth(service, status, security):
        return "public"

    if security == "LOCKED" or status == "423":
        return "locked"
    if security in {"NOT_FOUND", "DATASTORE_MODE"} or status == "404":
        return "not_found"
    if security == "RATE_LIMITED" or status == "429":
        return "rate_limited"
    if security in {"PROTECTED", "WRITE_DENIED", "RULES_VERSION_ERROR"}:
        return "protected"
    if status in {"401", "403"}:
        return "protected"
    return "unknown"


def derive_auth_verdict(service: str, status: str, security: str) -> str:
    """Verdict for an authenticated retry result.

    Returns one of: public, still_protected, app_check, not_found, error, unknown.
    """
    if security in TRANSPORT_SECURITY:
        return "error"
    if security == "APP_CHECK":
        return "app_check"
    if security in {"PUBLIC", "PUBLIC_AUTH", "PUBLIC_SA"} or status == "200":
        return "public"
    if security == "NOT_FOUND" or status == "404":
        return "not_found"
    if security == "PROTECTED" or status in {"401", "403"}:
        return "still_protected"
    return "unknown"


def _is_public_unauth(service: str, status: str, security: str) -> bool:
    """Public-unauth rule — matches each scanner's `_is_result_public` logic."""
    if status == "200" and security != "NO_CONFIG":
        return True
    if security == "PUBLIC":
        return True
    if security == "PUBLIC_DB_NONEXISTENT_COLLECTION":
        return True
    if security == "SOURCE_LEAK":
        return True
    # Cloud Functions: 400/405/415/500 with security=PUBLIC already covered above
    # (the scanner stamps security=PUBLIC on those). This branch is a safety net
    # if a raw status slips through without the stamp.
    if service == "cloud_functions" and status in {"400", "405", "415", "500"}:
        return True
    return False


def is_write_method(method: str) -> bool:
    return method.upper() in {"POST", "PUT", "DELETE", "PATCH"}
