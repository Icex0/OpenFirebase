from __future__ import annotations

import logging
import re
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import SessionLocal
from ..ingest.importer import import_extracted_projects, import_scan_document
from ..scanner.items_parser import parse_items_file
from ..scanner.runner import ScannerError, run_scan
from ..storage.minio_client import (
    delete_object,
    get_object,
    object_exists,
    put_object_stream,
    try_get_object,
)


from .models import Scan, ScanBundle, ScanLog, ScanStage, ScanStatus
from .pubsub import bus
from .repository import ScanRepository
from .schemas import ScanOptions


@dataclass
class PreparedBundle:
    """A bundle whose bytes are already on disk (in an UploadFile's spooled
    temp file) and whose SHA-256 + size have been computed by streaming.

    The ``fileobj`` is only drained if ``bundles/{sha256}`` is a cache miss;
    duplicates across users/scans reuse the existing blob for free.
    """
    filename: str
    sha256: str
    size: int
    fileobj: BinaryIO


def _bundle_key(sha256: str) -> str:
    return f"bundles/{sha256}"


async def gc_bundle_blob(session: AsyncSession, sha256: str) -> None:
    """Delete ``bundles/{sha256}`` if no ScanBundle still references it.

    Caller is responsible for ensuring the dereferencing DB writes (row
    delete / scan delete cascade) have been committed before calling —
    otherwise the ref count will still include the row we're trying to GC.
    """
    still_ref = await session.scalar(
        select(ScanBundle.sha256).where(ScanBundle.sha256 == sha256).limit(1)
    )
    if still_ref is None:
        await delete_object(_bundle_key(sha256))

log = logging.getLogger(__name__)


# ---------- Log-line patterns used to drive stage transitions ----------

_ITEMS_SAVED_RE = re.compile(r"Results have been saved to\s+(\S+firebase_items\.txt)")
_SCANNING_RE = re.compile(r"\[INF\]\s+(Testing|Scanning)\s+", re.IGNORECASE)


async def create_scan(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    bundles: list[PreparedBundle],
    options: ScanOptions,
) -> Scan:
    # Summary filename for the UI: first bundle, plus "(+N more)" when batched.
    if not bundles:
        # Manual mode: synthesise a name from the project IDs.
        ids = (options.project_ids or "").split(",") if options.project_ids else []
        if not ids:
            display = "manual scan"
        elif len(ids) == 1:
            display = f"manual: {ids[0]}"
        else:
            display = f"manual: {ids[0]} (+{len(ids) - 1} more)"
    else:
        first_name = bundles[0].filename
        display = first_name if len(bundles) == 1 else f"{first_name} (+{len(bundles) - 1} more)"
    scan = Scan(
        user_id=user_id,
        filename=display[:255],
        status=ScanStatus.queued.value,
        stage=ScanStage.queued.value,
        options=options.to_storable(),
    )
    repo = ScanRepository(session)
    await repo.add(scan)

    # Content-addressed storage: HEAD-check the canonical `bundles/{sha256}`
    # key, and only stream-upload bytes we haven't seen before. Duplicate
    # uploads (same sha twice in one request, or a rescan of an existing
    # blob) cost zero MinIO bytes. De-dup within a single upload too so we
    # don't re-upload the same sha back-to-back.
    seen_shas: set[str] = set()
    for b in bundles:
        if b.sha256 not in seen_shas:
            seen_shas.add(b.sha256)
            if not await object_exists(_bundle_key(b.sha256)):
                b.fileobj.seek(0)
                await put_object_stream(key=_bundle_key(b.sha256), fileobj=b.fileobj)
        session.add(
            ScanBundle(
                scan_id=scan.id,
                filename=b.filename,
                sha256=b.sha256,
                size_bytes=b.size,
            )
        )

    await session.commit()
    return scan


# ---------- Helpers ----------

async def _set_stage(scan_id: uuid.UUID, stage: ScanStage, *, status: ScanStatus) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        scan.stage = stage.value
        scan.status = status.value
        if stage is ScanStage.extracting and scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        if stage in (ScanStage.done, ScanStage.failed):
            scan.finished_at = datetime.now(timezone.utc)
        await session.commit()
    await bus.publish(
        scan_id, {"type": "stage", "stage": stage.value, "status": status.value}
    )


async def _persist_extracted(scan_id: uuid.UUID, items_path: Path) -> None:
    """Parse ``firebase_items.txt`` and replace the scan's project rows.

    Called mid-run so the UI shows projects + extracted data before the scan
    phase finishes. The final ``scan.json`` ingestion will overwrite this.
    """
    projects = parse_items_file(items_path)
    if not projects:
        return
    doc = {"projects": projects}
    async with SessionLocal() as session:
        scan = await ScanRepository(session).get_for_update(scan_id)
        if scan is None:
            return
        import_extracted_projects(scan=scan, doc=doc)
        await session.commit()
    await bus.publish(scan_id, {"type": "extracted"})


# ---------- Log sink (persists + publishes + drives stage) ----------

class _LogSink:
    """Callable log handler for the streaming runner.

    Responsibilities:
      * Persist every line to ``scan_logs`` (sequential seq per scan).
      * Redact known secrets (password, google id token) before storage.
      * Publish to the in-memory pub/sub so the SSE stream sees it live.
      * Detect two stage markers from the tool's output:
          - "Results have been saved to .../firebase_items.txt" → parse &
            persist projects (fire-and-forget; never blocks the pump).
          - "[INF] Testing ... access" → flip stage to ``scanning``.
    """

    def __init__(self, scan_id: uuid.UUID, *, options: ScanOptions) -> None:
        self.scan_id = scan_id
        self._seq: int | None = None
        self._secrets: list[str] = []
        if options.auth_password:
            self._secrets.append(options.auth_password)
        if options.google_id_token:
            self._secrets.append(options.google_id_token)
        self._stage_scanning_seen = False
        self._items_task: "uuid.UUID | None" = None  # placeholder for type checker

    def _redact(self, line: str) -> str:
        for secret in self._secrets:
            if secret and secret in line:
                line = line.replace(secret, "***")
        return line

    async def __call__(self, stream: str, line: str) -> None:
        line = self._redact(line)
        async with SessionLocal() as session:
            if self._seq is None:
                self._seq = await _next_seq(session, self.scan_id)
            seq = self._seq
            self._seq += 1
            session.add(ScanLog(scan_id=self.scan_id, seq=seq, stream=stream, line=line))
            await session.commit()
        await bus.publish(
            self.scan_id,
            {"type": "log", "seq": seq, "stream": stream, "line": line},
        )
        await self._react(line)

    async def system(self, line: str) -> None:
        await self("system", line)

    async def _react(self, line: str) -> None:
        if m := _ITEMS_SAVED_RE.search(line):
            path = Path(m.group(1).strip())
            # Fire-and-forget: persisting shouldn't block the stdout pump,
            # and failures must not crash the scan.
            import asyncio as _a
            _a.create_task(self._safe_persist(path))
        if not self._stage_scanning_seen and _SCANNING_RE.search(line):
            self._stage_scanning_seen = True
            import asyncio as _a
            _a.create_task(_set_stage(self.scan_id, ScanStage.scanning, status=ScanStatus.running))

    async def _safe_persist(self, path: Path) -> None:
        try:
            await _persist_extracted(self.scan_id, path)
        except Exception:
            log.exception("failed to persist extracted items")


async def _next_seq(session: AsyncSession, scan_id: uuid.UUID) -> int:
    current = await session.scalar(
        select(func.coalesce(func.max(ScanLog.seq), 0)).where(ScanLog.scan_id == scan_id)
    )
    return int(current or 0) + 1


# ---------- Main background task ----------

async def execute_scan(scan_id: uuid.UUID) -> None:
    """Run a full scan: download APK → run OpenFirebase once → ingest JSON → cleanup."""
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        from .secrets import decrypt_option_secrets

        options = ScanOptions.model_validate(
            decrypt_option_secrets(scan.options or {})
        )

    sink = _LogSink(scan_id, options=options)

    # Cancel wiring: backend publishes a `{"type": "cancel"}` event on the
    # bus; we flip this Event, which the runner watches to kill the child.
    import asyncio as _a
    cancel_event = _a.Event()
    cancel_q = await bus.subscribe(scan_id)

    async def _watch_cancel() -> None:
        while True:
            try:
                ev = await cancel_q.get()
            except _a.CancelledError:
                return
            if isinstance(ev, dict) and ev.get("type") == "cancel":
                cancel_event.set()
                return

    cancel_watcher = _a.create_task(_watch_cancel())

    try:
        manual = options.mode == "manual"
        bundle_rows: list[tuple[str, str]] = []  # (filename, sha256)

        if manual:
            # Manual mode skips extraction — there's no APK to unpack.
            await _set_stage(scan_id, ScanStage.scanning, status=ScanStatus.running)
        else:
            await _set_stage(scan_id, ScanStage.extracting, status=ScanStatus.running)
            async with SessionLocal() as session:
                rows = (
                    await session.execute(
                        select(ScanBundle.filename, ScanBundle.sha256)
                        .where(ScanBundle.scan_id == scan_id)
                    )
                ).all()
                bundle_rows = [(r[0], r[1]) for r in rows]
            if not bundle_rows:
                raise ScannerError("no input bundles found for scan")

        with tempfile.TemporaryDirectory(prefix="ofw-scan-") as tmp:
            tmp_path = Path(tmp)
            input_dir: Path | None = None
            if not manual:
                input_dir = tmp_path / "input"
                input_dir.mkdir()
                for name, sha in bundle_rows:
                    data = await get_object(_bundle_key(sha))
                    (input_dir / name).write_bytes(data)
            output_dir = tmp_path / "output"

            # Materialise any side-loaded custom wordlists / payloads from MinIO.
            async def _fetch(slot: str) -> Path | None:
                data = await try_get_object(f"uploads/{scan_id}/{slot}")
                if data is None:
                    return None
                p = tmp_path / slot
                p.write_bytes(data)
                return p

            fuzz_c = await _fetch("fuzz_collections.txt") if options.fuzz_collections == "custom" else None
            fuzz_f = await _fetch("fuzz_functions.txt") if options.fuzz_functions == "custom" else None
            write_rtdb_path = await _fetch("write_rtdb.json") if options.write_rtdb else None
            write_storage_path = await _fetch("write_storage.bin") if options.write_storage else None

            project_id_path: Path | None = None
            private_key_path: Path | None = None
            if manual:
                # project_id_file may have been uploaded; otherwise rely on inline list.
                project_id_path = await _fetch("project_ids.txt")
                # Private key: prefer uploaded file, else materialise the pasted PEM.
                private_key_path = await _fetch("private_key.pem")
                if private_key_path is None and options.private_key:
                    private_key_path = tmp_path / "private_key.pem"
                    private_key_path.write_text(options.private_key)

            scan_doc = await run_scan(
                input_dir=input_dir,
                output_dir=output_dir,
                options=options,
                on_line=sink,
                fuzz_collections_custom=fuzz_c,
                fuzz_functions_custom=fuzz_f,
                write_rtdb_custom=write_rtdb_path,
                write_storage_custom=write_storage_path,
                project_id_file=project_id_path,
                private_key_file=private_key_path,
                cancel_event=cancel_event,
            )

            async with SessionLocal() as session:
                scan = await ScanRepository(session).get_for_update(scan_id)
                if scan is None:
                    return
                await import_scan_document(session, scan=scan, doc=scan_doc)
                scan.stage = ScanStage.done.value
                scan.status = ScanStatus.done.value
                scan.finished_at = datetime.now(timezone.utc)
                await session.commit()
        await bus.publish(
            scan_id,
            {"type": "stage", "stage": ScanStage.done.value, "status": ScanStatus.done.value},
        )
        await bus.publish(scan_id, {"type": "end"})

    except ScannerError as exc:
        if cancel_event.is_set():
            await sink.system("[info] cancelled by user")
            await _finalize_cancelled(scan_id)
        else:
            log.exception("scan failed")
            await sink.system(f"[error] {exc}")
            await _fail(scan_id, str(exc))
    except Exception as exc:  # pragma: no cover
        if cancel_event.is_set():
            await sink.system("[info] cancelled by user")
            await _finalize_cancelled(scan_id)
        else:
            log.exception("scan failed unexpectedly")
            await sink.system(f"[fatal] {type(exc).__name__}")
            await _fail(scan_id, f"internal error: {type(exc).__name__}")
    finally:
        cancel_watcher.cancel()
        await bus.unsubscribe(scan_id, cancel_q)
    # Note: uploaded bundles + auxiliary slot files are intentionally *kept*
    # in MinIO so the user can re-scan without re-uploading. They get purged
    # when the user explicitly deletes the scan (see DELETE /scans/{id}).


async def _finalize_cancelled(scan_id: uuid.UUID) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.cancelled.value
        scan.stage = ScanStage.failed.value
        scan.error_message = "cancelled by user"
        scan.finished_at = datetime.now(timezone.utc)
        await session.commit()
    await bus.publish(
        scan_id,
        {
            "type": "stage",
            "stage": ScanStage.failed.value,
            "status": ScanStatus.cancelled.value,
        },
    )
    await bus.publish(scan_id, {"type": "end"})


async def _fail(scan_id: uuid.UUID, message: str) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.failed.value
        scan.stage = ScanStage.failed.value
        scan.error_message = message
        scan.finished_at = datetime.now(timezone.utc)
        await session.commit()
    await bus.publish(
        scan_id,
        {
            "type": "stage",
            "stage": ScanStage.failed.value,
            "status": ScanStatus.failed.value,
            "error": message,
        },
    )
    await bus.publish(scan_id, {"type": "end"})
