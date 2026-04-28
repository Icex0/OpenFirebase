"""Storage browsing + cleanup.

Exposes the user's *unique* APK/IPA blobs (content-addressed by SHA-256),
not per-scan copies — uploading the same APK twice, or rescanning, costs
zero extra MinIO bytes, and this view reflects that by collapsing on
``sha256``. All queries are scoped by ``scans.user_id`` — a user can
never enumerate or touch another user's objects, even though the MinIO
root creds on the backend technically *could*.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.models import User
from ..auth.users import current_active_user
from ..db import get_session
from ..scans.models import Scan, ScanBundle
from ..scans.service import gc_bundle_blob
from .minio_client import delete_object

router = APIRouter(prefix="/storage", tags=["storage"])


_AUX_SLOTS = (
    "fuzz_collections.txt",
    "fuzz_functions.txt",
    "write_rtdb.json",
    "write_storage.bin",
    "project_ids.txt",
    "private_key.pem",
)


class StoredScanRef(BaseModel):
    scan_id: uuid.UUID
    scan_filename: str
    created_at: str


class StoredBlob(BaseModel):
    sha256: str
    size: int
    filenames: list[str]
    scans: list[StoredScanRef]


@router.get("/bundles", response_model=list[StoredBlob])
async def list_stored_bundles(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> list[StoredBlob]:
    """List each unique bundle blob the caller's scans reference.

    One row per SHA-256 — if two scans (original + rescan, say) share the
    same APK, they both appear under ``scans`` but the ``size`` is counted
    once, matching actual MinIO footprint.
    """
    rows = (
        await session.execute(
            select(
                ScanBundle.sha256,
                ScanBundle.size_bytes,
                ScanBundle.filename,
                Scan.id,
                Scan.filename,
                Scan.created_at,
            )
            .join(Scan, Scan.id == ScanBundle.scan_id)
            .where(Scan.user_id == user.id)
            .order_by(Scan.created_at.desc())
        )
    ).all()

    grouped: dict[str, StoredBlob] = {}
    seen_names: dict[str, set[str]] = {}
    seen_scans: dict[str, set[uuid.UUID]] = {}
    for sha, size, bundle_name, scan_id, scan_filename, created_at in rows:
        blob = grouped.get(sha)
        if blob is None:
            blob = StoredBlob(sha256=sha, size=int(size), filenames=[], scans=[])
            grouped[sha] = blob
            seen_names[sha] = set()
            seen_scans[sha] = set()
        if bundle_name not in seen_names[sha]:
            seen_names[sha].add(bundle_name)
            blob.filenames.append(bundle_name)
        if scan_id not in seen_scans[sha]:
            seen_scans[sha].add(scan_id)
            blob.scans.append(
                StoredScanRef(
                    scan_id=scan_id,
                    scan_filename=scan_filename,
                    created_at=_iso(created_at),
                )
            )
    return list(grouped.values())


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@router.delete("/bundles/{sha256}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_stored_blob(
    sha256: str,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Drop every reference to this blob from the caller's scans, then GC
    the blob if no other user still references it.

    Findings on each affected scan are preserved; only the input bytes are
    freed. Rescanning any of those scans will no longer work.
    """
    # Collect scans owned by the caller that reference this blob.
    scan_ids = list(
        (await session.scalars(
            select(ScanBundle.scan_id)
            .join(Scan, Scan.id == ScanBundle.scan_id)
            .where(ScanBundle.sha256 == sha256, Scan.user_id == user.id)
        )).all()
    )
    if not scan_ids:
        raise HTTPException(404, "Blob not found")

    await session.execute(
        ScanBundle.__table__.delete().where(
            ScanBundle.sha256 == sha256,
            ScanBundle.scan_id.in_(scan_ids),
        )
    )
    await session.commit()

    await gc_bundle_blob(session, sha256)

    # Aux uploads are keyed per-scan, not by sha. Clean them up for every
    # scan that just lost its bundle — rescan won't work anyway.
    for sid in scan_ids:
        for slot in _AUX_SLOTS:
            await delete_object(f"uploads/{sid}/{slot}")
