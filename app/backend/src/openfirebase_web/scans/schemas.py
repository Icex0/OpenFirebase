from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class ProbeResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    status: str
    security: str
    verdict: str
    message: str | None = None
    response_content: str | None = None
    identity: dict[str, Any] | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    service: str
    probe: str
    url: str
    unauth: ProbeResult
    auth: ProbeResult | None = None
    resource: dict[str, Any] | None = None


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    project_id: str
    package_names: list[str] | None = None
    extracted_items: dict[str, Any] | None = None
    findings: list[FindingRead] = []


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    filename: str
    status: str
    stage: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    tool_version: str | None = None
    error_message: str | None = None
    bundle_filenames: list[str] = []
    options: dict[str, Any] | None = None

    @field_validator("options", mode="before")
    @classmethod
    def _redact_option_secrets(cls, v: Any) -> Any:
        # Options persisted in DB keep the raw credentials so the worker can
        # authenticate on rescan. Strip them here so API responses never leak.
        if not isinstance(v, dict):
            return v
        redacted = dict(v)
        for key in ("auth_password", "google_id_token", "private_key"):
            redacted.pop(key, None)
        return redacted

    @model_validator(mode="before")
    @classmethod
    def _extract_bundle_filenames(cls, data: Any) -> Any:
        # Skip if `bundles` isn't eager-loaded — touching it here would
        # trigger a sync lazy-load and raise MissingGreenlet.
        try:
            from sqlalchemy import inspect as _sa_inspect

            insp = _sa_inspect(data, raiseerr=False)
            if insp is not None and "bundles" not in insp.unloaded:
                names = [b.filename for b in data.bundles]
            else:
                names = []
        except Exception:
            names = []
        try:
            object.__setattr__(data, "bundle_filenames", names)
        except Exception:
            pass
        return data


class ScanDetail(ScanSummary):
    schema_version: str | None = None
    projects: list[ProjectRead] = []
    raw_document: dict[str, Any] | None = None


# ---------- Scan options ----------

WordlistChoice = Literal["off", "top-50", "top-250", "top-500", "custom"]

# Allow letters, digits, underscore, dash, dot. Comma-separated lists handled via split.
_SAFE_IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}$")
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9_.\- ]{1,256}$")
# Firebase project IDs / package names / bundle IDs allow ., -, _.
_SAFE_PROJECT_ID = re.compile(r"^[a-z][a-z0-9_\-]{0,62}$")
_SAFE_BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")
_SAFE_API_KEY = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
_SAFE_APP_ID = re.compile(r"^[A-Za-z0-9_:.\-]{1,128}$")
_SAFE_SHA1 = re.compile(r"^[A-Fa-f0-9]{40}$|^([A-Fa-f0-9]{2}:){19}[A-Fa-f0-9]{2}$")
_SAFE_REGION = re.compile(r"^[a-z][a-z0-9\-]{1,31}$")
_SAFE_FN_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{0,63}$")
_SAFE_REFERER = re.compile(r"^[A-Za-z0-9_.\-:/]{1,256}$")


def _validate_ident_list(v: str | None, *, max_items: int = 32) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if not v:
        return None
    parts = [p.strip() for p in v.split(",") if p.strip()]
    if len(parts) > max_items:
        raise ValueError(f"too many items (max {max_items})")
    for p in parts:
        if not _SAFE_IDENT.match(p):
            raise ValueError(f"invalid identifier: {p!r}")
    return ",".join(parts)


ScanMode = Literal["bundle", "manual"]


class ScanOptions(BaseModel):
    """User-submitted scan configuration. Every string field that flows into
    the OpenFirebase argv is strictly validated to reject control chars and
    shell metacharacters. The runner uses ``create_subprocess_exec`` (argv
    list, no shell), so these validators are defence-in-depth on top of that.
    """

    model_config = ConfigDict(extra="forbid")

    # Mode — determines whether bundles or manual identifiers drive the scan.
    mode: ScanMode = "bundle"

    # Read scope
    read_rtdb: bool = True
    read_storage: bool = True
    read_config: bool = True
    read_firestore: bool = True
    read_functions: bool = True

    # Fuzzing
    fuzz_collections: WordlistChoice = "off"
    fuzz_functions: WordlistChoice = "off"
    collection_name: str | None = Field(default=None, max_length=256)

    # Speed-vs-accuracy tradeoff for Cloud Functions probing. When true, project
    # IDs with no extracted function URLs or callable names skip the GCS source
    # bucket probe entirely (and therefore skip fuzzing for that project too).
    skip_gcs_probing: bool = False

    # Cloud Functions targeting (manual mode mostly).
    function_name: str | None = Field(default=None, max_length=512)
    function_region: str | None = Field(default=None, max_length=256)

    # Write testing
    write_storage: bool = False
    write_firestore: bool = False
    write_rtdb: bool = False
    write_firestore_value: str = Field(default="unauth_write_check", max_length=128)

    # Authentication
    auth_enabled: bool = False
    auth_email: EmailStr | None = None
    auth_password: str | None = Field(default=None, max_length=256)
    google_id_token: str | None = Field(default=None, max_length=8192)

    # Service-account auth (manual mode). Email + raw PEM private key.
    service_account: EmailStr | None = None
    private_key: str | None = Field(default=None, max_length=16_384)

    # Manual mode: identifiers normally extracted from a bundle.
    project_ids: str | None = Field(default=None, max_length=2048)
    app_id: str | None = Field(default=None, max_length=128)
    api_key: str | None = Field(default=None, max_length=128)
    cert_sha1: str | None = Field(default=None, max_length=64)
    package_name: str | None = Field(default=None, max_length=128)
    referer: str | None = Field(default=None, max_length=256)
    ios_bundle_id: str | None = Field(default=None, max_length=128)

    @field_validator("collection_name")
    @classmethod
    def _v_collection_name(cls, v: str | None) -> str | None:
        return _validate_ident_list(v, max_items=16)

    @field_validator("write_firestore_value")
    @classmethod
    def _v_write_firestore_value(cls, v: str) -> str:
        if not _SAFE_TEXT.match(v):
            raise ValueError("only letters, digits, _, -, ., space allowed")
        return v

    @field_validator("google_id_token")
    @classmethod
    def _v_google_token(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not re.fullmatch(r"[A-Za-z0-9_\-\.]+", v):
            raise ValueError("must be a JWT-format token")
        return v

    @field_validator("auth_password")
    @classmethod
    def _v_auth_password(cls, v: str | None) -> str | None:
        if v is None:
            return None
        # Reject only control chars; passwords may legitimately contain symbols.
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("password may not contain control characters")
        return v

    @field_validator("project_ids")
    @classmethod
    def _v_project_ids(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        # Accept comma, newline, or whitespace separators.
        parts = [p.strip() for p in re.split(r"[\s,]+", v) if p.strip()]
        if len(parts) > 256:
            raise ValueError("too many project IDs (max 256)")
        for p in parts:
            if not _SAFE_PROJECT_ID.match(p):
                raise ValueError(f"invalid project id: {p!r}")
        return ",".join(parts)

    @field_validator("function_name")
    @classmethod
    def _v_function_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        parts = [p.strip() for p in v.split(",") if p.strip()]
        for p in parts:
            if not _SAFE_FN_NAME.match(p):
                raise ValueError(f"invalid function name: {p!r}")
        return ",".join(parts)

    @field_validator("function_region")
    @classmethod
    def _v_function_region(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        parts = [p.strip() for p in v.split(",") if p.strip()]
        for p in parts:
            if not _SAFE_REGION.match(p):
                raise ValueError(f"invalid region: {p!r}")
        return ",".join(parts)

    @field_validator("app_id")
    @classmethod
    def _v_app_id(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not _SAFE_APP_ID.match(v):
            raise ValueError("invalid app id")
        return v

    @field_validator("api_key")
    @classmethod
    def _v_api_key(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not _SAFE_API_KEY.match(v):
            raise ValueError("invalid api key")
        return v

    @field_validator("cert_sha1")
    @classmethod
    def _v_cert_sha1(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not _SAFE_SHA1.match(v):
            raise ValueError("cert_sha1 must be a 40-char hex (optionally colon-separated)")
        return v

    @field_validator("package_name", "ios_bundle_id")
    @classmethod
    def _v_bundle_id(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not _SAFE_BUNDLE_ID.match(v):
            raise ValueError("invalid bundle / package identifier")
        return v

    @field_validator("referer")
    @classmethod
    def _v_referer(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not _SAFE_REFERER.match(v):
            raise ValueError("invalid referer")
        return v

    @field_validator("private_key")
    @classmethod
    def _v_private_key(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if "BEGIN" not in v or "PRIVATE KEY" not in v:
            raise ValueError("private_key must be a PEM block")
        return v

    @model_validator(mode="after")
    def _v_combinations(self) -> "ScanOptions":
        """Mirror the hard validation rules in ``openfirebase/core/cli.py`` so we
        reject impossible combinations before kicking off a scan (which would
        otherwise fail with exit 2 mid-run)."""
        # Auth credentials must be coherent.
        if self.auth_enabled:
            has_email_pw = bool(self.auth_email and self.auth_password)
            has_google = bool(self.google_id_token)
            if not (has_email_pw or has_google):
                raise ValueError(
                    "authenticated retry needs an email + password or a Google ID token"
                )

        # Service account ↔ private key must come together.
        if bool(self.service_account) != bool(self.private_key):
            raise ValueError(
                "service account email and private key must be provided together"
            )

        # A Google OAuth ID token is bound to one Firebase project's OAuth
        # client (for Android, also to package_name + SHA-1), so it only
        # authenticates the project whose client issued it. Mirror the CLI's
        # single-project rule from validate_google_id_token_options.
        if self.google_id_token and self.mode == "manual":
            ids = [p for p in (self.project_ids or "").split(",") if p]
            if len(ids) > 1:
                raise ValueError(
                    "google_id_token only supports a single project ID — "
                    "the token is bound to one Firebase project's OAuth client"
                )

        if self.mode == "manual":
            ids = [p for p in (self.project_ids or "").split(",") if p]
            has_ids = bool(ids)

            if self.read_config and has_ids and not (self.app_id and self.api_key):
                raise ValueError(
                    "--read-config with project IDs requires both --app-id and --api-key"
                )

            if (
                self.read_functions
                and has_ids
                and not self.function_name
                and self.fuzz_functions == "off"
            ):
                raise ValueError(
                    "--read-functions with project IDs requires --function-name or a fuzz wordlist"
                )

            if self.auth_enabled and has_ids:
                if not self.api_key:
                    raise ValueError(
                        "authenticated retry with project IDs requires --api-key"
                    )
                if len(ids) > 1:
                    raise ValueError(
                        "authenticated retry only supports a single project ID"
                    )

        return self

    def to_storable(self) -> dict[str, Any]:
        """Full options dict for DB persistence. Credential fields are Fernet-
        encrypted (keyed off ``app_secret``) so a raw DB dump can't recover
        them; the worker decrypts on load. The API layer
        (``ScanSummary._redact_option_secrets``) drops them entirely from
        client responses."""
        from .secrets import encrypt_option_secrets

        return encrypt_option_secrets(self.model_dump())


# ---------- Logs ----------

class LogLine(BaseModel):
    seq: int
    ts: datetime
    stream: str
    line: str
