from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from typing import Annotated, Callable

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import Response, StreamingResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.models import User
from ..auth.users import current_active_user, get_user_from_token
from ..db import SessionLocal, get_session
from ..storage.minio_client import (
    copy_object,
    delete_object,
    put_object,
)
from .models import Scan, ScanBundle, ScanLog
from .pubsub import bus
from .repository import ScanRepository
from .schemas import (
    FindingRead,
    LogLine,
    ProbeResult,
    ProjectRead,
    ScanDetail,
    ScanOptions,
    ScanSummary,
)
from .service import PreparedBundle, create_scan, gc_bundle_blob

router = APIRouter(prefix="/scans", tags=["scans"])


# ---------- Limits ----------
# Per-bundle hard cap. Bundles are stream-hashed and stream-uploaded to
# MinIO, so this bounds disk usage in /tmp (UploadFile spools there),
# not RAM. 2 GiB handles fat APKs with bundled ML models; larger files
# would need presigned direct-to-MinIO uploads (not implemented).
MAX_APK_BYTES = 2 * 1024 * 1024 * 1024
MAX_WORDLIST_BYTES = 2 * 1024 * 1024
MAX_PAYLOAD_BYTES = 20 * 1024 * 1024
MAX_LOG_PAGE = 2000
_HASH_CHUNK = 1024 * 1024  # 1 MiB read chunks while hashing spooled bundles


def _upload_key(scan_id: uuid.UUID, slot: str) -> str:
    # ``slot`` is whitelisted server-side — no user-controlled path segments.
    return f"uploads/{scan_id}/{slot}"


async def _read_bounded(file: UploadFile, limit: int, label: str) -> bytes:
    data = await file.read()
    if len(data) > limit:
        raise HTTPException(413, f"{label} exceeds {limit} bytes")
    return data


async def _hash_bundle(file: UploadFile, limit: int) -> tuple[str, int]:
    """Stream-hash an UploadFile without pulling it fully into RAM.

    Reads the spooled temp file in ``_HASH_CHUNK``-sized chunks, trips the
    size cap incrementally, and rewinds to offset 0 so the caller can pass
    the same fileobj straight to ``put_object_stream``.
    """
    hasher = hashlib.sha256()
    size = 0
    while True:
        chunk = await file.read(_HASH_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, f"bundle exceeds {limit} bytes: {file.filename!r}")
        hasher.update(chunk)
    if size == 0:
        raise HTTPException(400, f"Empty file: {file.filename!r}")
    await file.seek(0)
    return hasher.hexdigest(), size


# ---------- Endpoints ----------

@router.get("", response_model=list[ScanSummary])
async def list_scans(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> list[ScanSummary]:
    scans = await ScanRepository(session).list_for_user(user.id)
    return [ScanSummary.model_validate(s) for s in scans]


@router.post("", response_model=ScanSummary, status_code=status.HTTP_201_CREATED)
async def upload_scan(
    files: Annotated[list[UploadFile] | None, File(description="One or more .apk/.ipa bundles (bundle mode only)")] = None,
    options: Annotated[str, Form(description="ScanOptions as JSON")] = "{}",
    fuzz_collections_file: Annotated[UploadFile | None, File()] = None,
    fuzz_functions_file: Annotated[UploadFile | None, File()] = None,
    write_rtdb_file: Annotated[UploadFile | None, File()] = None,
    write_storage_file: Annotated[UploadFile | None, File()] = None,
    project_id_file: Annotated[UploadFile | None, File()] = None,
    private_key_file: Annotated[UploadFile | None, File()] = None,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> ScanSummary:
    try:
        opts_dict = json.loads(options) if options else {}
    except json.JSONDecodeError:
        raise HTTPException(400, "options must be valid JSON")
    try:
        opts = ScanOptions.model_validate(opts_dict)
    except ValidationError as exc:
        raise HTTPException(422, exc.errors())

    if opts.mode == "bundle":
        if not files:
            raise HTTPException(400, "At least one bundle file is required")
        for f in files:
            if not f.filename or not f.filename.lower().endswith((".apk", ".ipa")):
                raise HTTPException(400, f"Upload must be .apk or .ipa: {f.filename!r}")
        # A Google OAuth ID token is bound to one app's OAuth client, so it
        # only authenticates the single project that token was captured from.
        # Mirror the CLI's --google-id-token + --app-dir rejection.
        if opts.google_id_token and len(files) > 1:
            raise HTTPException(
                400,
                "google_id_token cannot be used with multiple bundle uploads — "
                "the token is bound to one app's OAuth client. Upload only the "
                "matching APK/IPA, or switch to manual mode with the matching project ID.",
            )
    else:
        if files:
            raise HTTPException(400, "Manual mode does not accept bundle files")
        if not opts.project_ids and project_id_file is None:
            raise HTTPException(400, "Manual mode requires project IDs (paste or file)")
        if opts.service_account and not (opts.private_key or private_key_file):
            raise HTTPException(400, "service_account requires a private key (paste or file)")

    # Custom uploads are only accepted when the matching option asks for them.
    if fuzz_collections_file and opts.fuzz_collections != "custom":
        raise HTTPException(400, "fuzz_collections_file requires fuzz_collections='custom'")
    if fuzz_functions_file and opts.fuzz_functions != "custom":
        raise HTTPException(400, "fuzz_functions_file requires fuzz_functions='custom'")
    if opts.fuzz_collections == "custom" and not fuzz_collections_file:
        raise HTTPException(400, "fuzz_collections='custom' requires fuzz_collections_file")
    if opts.fuzz_functions == "custom" and not fuzz_functions_file:
        raise HTTPException(400, "fuzz_functions='custom' requires fuzz_functions_file")

    # Stream-hash each bundle (bounded) — the bytes stay in the UploadFile's
    # spooled tempfile on disk and never land in RAM. We'll hand the fileobj
    # to create_scan which will stream-upload to MinIO on cache miss.
    # Collapse duplicate basenames to avoid collisions in the scan tmp dir —
    # last-wins with a numeric suffix.
    bundles: list[PreparedBundle] = []
    if opts.mode == "bundle":
        seen: dict[str, int] = {}
        for f in files or []:
            sha, size = await _hash_bundle(f, MAX_APK_BYTES)
            # Strip any folder path components from browser-supplied filenames.
            base = (f.filename or "bundle").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if base in seen:
                seen[base] += 1
                stem, _, ext = base.rpartition(".")
                base = f"{stem}_{seen[base]}.{ext}" if stem else f"{base}_{seen[base]}"
            else:
                seen[base] = 0
            bundles.append(
                PreparedBundle(filename=base, sha256=sha, size=size, fileobj=f.file)
            )

    scan = await create_scan(
        session, user_id=user.id, bundles=bundles, options=opts,
    )

    # Side-loaded custom wordlists / payloads → MinIO under the scan's namespace.
    async def _stash(
        upload: UploadFile | None,
        slot: str,
        limit: int,
        label: str,
        *,
        validator: Callable[[bytes], None] | None = None,
    ) -> None:
        if upload is None:
            return
        data = await _read_bounded(upload, limit, label)
        if not data:
            raise HTTPException(400, f"{label} is empty")
        if validator is not None:
            validator(data)
        await put_object(key=_upload_key(scan.id, slot), data=data)

    def _validate_json(data: bytes) -> None:
        try:
            json.loads(data)
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"RTDB payload must be valid JSON: {exc.msg}")

    await _stash(fuzz_collections_file, "fuzz_collections.txt", MAX_WORDLIST_BYTES, "fuzz_collections")
    await _stash(fuzz_functions_file, "fuzz_functions.txt", MAX_WORDLIST_BYTES, "fuzz_functions")
    await _stash(
        write_rtdb_file, "write_rtdb.json", MAX_PAYLOAD_BYTES,
        "write_rtdb payload", validator=_validate_json,
    )
    await _stash(write_storage_file, "write_storage.bin", MAX_PAYLOAD_BYTES, "write_storage payload")
    await _stash(project_id_file, "project_ids.txt", MAX_WORDLIST_BYTES, "project_id_file")
    await _stash(private_key_file, "private_key.pem", MAX_PAYLOAD_BYTES, "private_key_file")

    # The scanner worker (separate container) picks up queued scans via
    # SELECT ... FOR UPDATE SKIP LOCKED; don't run the scan in this process.
    return ScanSummary.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> ScanDetail:
    scan = await ScanRepository(session).get(scan_id, user.id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return _serialize(scan)


@router.get("/{scan_id}/logs", response_model=list[LogLine])
async def list_logs(
    scan_id: uuid.UUID,
    after_seq: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=MAX_LOG_PAGE),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> list[LogLine]:
    # BAC: ensure the scan belongs to this user before returning any logs.
    scan = await session.scalar(
        select(Scan.id).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    if scan is None:
        raise HTTPException(404, "Scan not found")

    stmt = (
        select(ScanLog)
        .where(ScanLog.scan_id == scan_id, ScanLog.seq > after_seq)
        .order_by(ScanLog.seq.asc())
        .limit(limit)
    )
    rows = (await session.scalars(stmt)).all()
    return [LogLine(seq=r.seq, ts=r.ts, stream=r.stream, line=r.line) for r in rows]


@router.get("/{scan_id}/stream")
async def stream_scan(
    scan_id: uuid.UUID,
    token: str = Query(..., description="JWT (EventSource can't send headers)"),
):
    """Server-Sent Events: live scan logs + stage transitions.

    Auth is via ``token`` query-string (EventSource does not support
    ``Authorization`` headers). Token is validated against the same JWT
    backend as the rest of the API. Over HTTPS, query-string tokens are
    encrypted in transit; avoid logging raw request URLs server-side.

    Uses a short-lived session for auth/authz checks and releases it before
    streaming, so the long-lived SSE response doesn't tie up a DB connection.
    """
    # Short-lived session: validate auth + scan access, then release.
    async with SessionLocal() as session:
        user = await get_user_from_token(token, session)
        if user is None:
            raise HTTPException(401, "Invalid token")

        scan = await session.scalar(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
        )
        if scan is None:
            raise HTTPException(404, "Scan not found")

        initial_stage = scan.stage
        initial_status = scan.status
        terminal = scan.status in {"done", "failed"}

    # Subscribe FIRST, then replay DB history, then stream live events.
    # Any event published between subscribe and replay is buffered in the
    # queue; the client dedupes by ``seq``. This closes the race where a
    # naive history-fetch-then-subscribe sequence would drop lines that
    # were written to the DB between the two calls.
    queue = await bus.subscribe(scan_id)

    async def event_gen():
        try:
            yield ": connected\n\n"
            yield _sse({"type": "snapshot", "stage": initial_stage, "status": initial_status})

            # Replay all log rows persisted so far.
            last_seq = 0
            async with SessionLocal() as session:
                rows = (
                    await session.scalars(
                        select(ScanLog)
                        .where(ScanLog.scan_id == scan_id)
                        .order_by(ScanLog.seq.asc())
                    )
                ).all()
            for r in rows:
                yield _sse({
                    "type": "log",
                    "seq": r.seq,
                    "stream": r.stream,
                    "line": r.line,
                })
                last_seq = r.seq

            if terminal:
                yield _sse({"type": "end"})
                return

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                # Drop duplicates we already replayed from history.
                if event.get("type") == "log" and event.get("seq", 0) <= last_seq:
                    continue
                yield _sse(event)
                if event.get("type") == "end":
                    return
        finally:
            await bus.unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


def _finding_read(f) -> FindingRead:
    """Build a FindingRead, pulling response_content/identity from the
    cached raw payload (those aren't normalised into columns)."""
    raw = f.raw or {}
    raw_unauth = raw.get("unauth") or {}
    raw_auth = raw.get("auth") or {}
    return FindingRead(
        id=f.id,
        service=f.service,
        probe=f.probe,
        url=f.url,
        unauth=ProbeResult(
            status=f.unauth_status,
            security=f.unauth_security,
            verdict=f.unauth_verdict,
            message=f.unauth_message,
            response_content=raw_unauth.get("response_content"),
        ),
        auth=(
            ProbeResult(
                status=f.auth_status,
                security=f.auth_security,
                verdict=f.auth_verdict,
                message=f.auth_message,
                response_content=raw_auth.get("response_content"),
                identity=raw_auth.get("identity"),
            )
            if f.auth_verdict
            else None
        ),
        resource=f.resource,
    )


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"


@router.get("/{scan_id}/download")
async def download_scan(
    scan_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
):
    scan = await ScanRepository(session).get(scan_id, user.id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if not scan.raw_document:
        raise HTTPException(409, "Scan is not done")
    body = json.dumps(scan.raw_document, indent=2, ensure_ascii=False)
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'},
    )


@router.post("/{scan_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(
    scan_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
):
    scan = await session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    if scan is None:
        raise HTTPException(404, "Scan not found")
    if scan.status not in ("queued", "running"):
        raise HTTPException(409, "Scan is not cancellable")

    was_queued = scan.status == "queued"
    scan.status = "cancelled"
    scan.stage = "failed"
    scan.error_message = "cancelled by user"
    from datetime import datetime, timezone
    scan.finished_at = datetime.now(timezone.utc)
    await session.commit()

    # For queued scans, flipping the DB row is enough — the worker will skip
    # it. For running scans, notify the worker so it kills the subprocess.
    if not was_queued:
        await bus.publish(scan_id, {"type": "cancel"})
    await bus.publish(
        scan_id,
        {"type": "stage", "stage": "failed", "status": "cancelled"},
    )
    await bus.publish(scan_id, {"type": "end"})


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
):
    # Snapshot the sha256 set BEFORE the cascade delete drops the ScanBundle
    # rows — we need it to decide which bundle blobs to GC afterwards.
    shas = set(
        (await session.scalars(
            select(ScanBundle.sha256).where(ScanBundle.scan_id == scan_id)
        )).all()
    )

    ok = await ScanRepository(session).delete(scan_id, user.id)
    await session.commit()
    if not ok:
        raise HTTPException(404, "Scan not found")

    # Only purge MinIO after the DB row is gone — if the delete races with an
    # in-flight rescan, the rescan will have failed on the scan lookup first.
    for sha in shas:
        await gc_bundle_blob(session, sha)
    for slot in _UPLOAD_SLOTS:
        await delete_object(f"uploads/{scan_id}/{slot}")


_UPLOAD_SLOTS = (
    "fuzz_collections.txt",
    "fuzz_functions.txt",
    "write_rtdb.json",
    "write_storage.bin",
    "project_ids.txt",
    "private_key.pem",
)


@router.post("/{scan_id}/rescan", response_model=ScanSummary, status_code=status.HTTP_201_CREATED)
async def rescan(
    scan_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> ScanSummary:
    """Clone an existing scan: copy its uploads to a new scan_id prefix and
    enqueue a fresh Scan row. The scanner worker polls and picks it up."""
    original = await session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    if original is None:
        raise HTTPException(404, "Scan not found")

    new_scan = Scan(
        user_id=user.id,
        filename=original.filename,
        status="queued",
        stage="queued",
        options=original.options,
    )
    session.add(new_scan)
    await session.flush()  # populate new_scan.id before we clone junction rows
    new_id = new_scan.id

    # Clone the ScanBundle junction rows — zero MinIO bytes moved, since the
    # blobs at ``bundles/{sha256}`` are shared across all scans that reference
    # them.
    src_bundles = (
        await session.execute(
            select(ScanBundle.filename, ScanBundle.sha256, ScanBundle.size_bytes)
            .where(ScanBundle.scan_id == scan_id)
        )
    ).all()
    for name, sha, size in src_bundles:
        session.add(
            ScanBundle(scan_id=new_id, filename=name, sha256=sha, size_bytes=size)
        )
    await session.commit()

    # Auxiliary uploads (wordlists, keys) are NOT content-addressed — per-scan
    # server-side copy, same as before.
    for slot in _UPLOAD_SLOTS:
        await copy_object(f"uploads/{scan_id}/{slot}", f"uploads/{new_id}/{slot}")

    return ScanSummary.model_validate(new_scan)


def _serialize(scan: Scan) -> ScanDetail:
    projects = [
        ProjectRead(
            id=p.id,
            project_id=p.project_id,
            package_names=p.package_names,
            extracted_items=p.extracted_items,
            findings=[_finding_read(f) for f in p.findings],
        )
        for p in scan.projects
    ]
    return ScanDetail(
        id=scan.id,
        filename=scan.filename,
        status=str(scan.status),
        stage=str(scan.stage),
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        tool_version=scan.tool_version,
        schema_version=scan.schema_version,
        error_message=scan.error_message,
        projects=projects,
        raw_document=scan.raw_document,
        options=scan.options,
    )
