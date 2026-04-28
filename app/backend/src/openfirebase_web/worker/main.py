"""Scan worker entrypoint.

Runs in its own container so the openfirebase subprocess (which parses
attacker-controlled APKs / IPAs via androguard) can't reach the backend's
DB / MinIO credentials, session secret, or network egress.

Polls Postgres for ``status='queued'`` scans, claims one atomically with
``FOR UPDATE SKIP LOCKED``, then hands it to the existing
:func:`execute_scan` pipeline. Live log lines / stage transitions are
published to the backend via Postgres ``NOTIFY`` (see :mod:`..scans.pubsub`).
"""
from __future__ import annotations

import asyncio
import logging
import signal
import uuid

from sqlalchemy import text

from ..auth import models as _auth_models  # noqa: F401 — registers the `user` table so the scans.user_id FK resolves.
from ..db import SessionLocal
from ..scans.service import execute_scan

log = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 2.0


async def _claim_one() -> uuid.UUID | None:
    """Atomically pick the oldest queued scan and flip it to ``running``.

    ``FOR UPDATE SKIP LOCKED`` makes this safe under multiple worker
    replicas — each worker grabs a different row. ``COALESCE`` on
    ``started_at`` covers manual-mode scans that skip the extracting stage
    (where ``_set_stage`` would otherwise set it).
    """
    sql = text("""
        WITH next AS (
          SELECT id FROM scans
          WHERE status = 'queued'
          ORDER BY created_at
          FOR UPDATE SKIP LOCKED
          LIMIT 1
        )
        UPDATE scans
        SET status = 'running',
            started_at = COALESCE(started_at, now())
        WHERE id IN (SELECT id FROM next)
        RETURNING id
    """)
    async with SessionLocal() as session:
        row = await session.execute(sql)
        scan_id = row.scalar_one_or_none()
        await session.commit()
    return scan_id


async def _recover_orphans() -> None:
    """Fail any scan stuck in ``running`` from a prior worker crash.

    Correct as long as there is one worker replica; with multiple workers
    you'd need a heartbeat column to tell crashed jobs from live ones.
    """
    async with SessionLocal() as session:
        result = await session.execute(text("""
            UPDATE scans
            SET status = 'failed',
                stage = 'failed',
                error_message = COALESCE(error_message,
                                         'worker restarted before scan finished'),
                finished_at = now()
            WHERE status = 'running'
            RETURNING id
        """))
        ids = [r[0] for r in result.all()]
        await session.commit()
    if ids:
        log.warning("recovered %d orphaned running scans: %s", len(ids), ids)


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Bucket is bootstrapped by the minio-init one-shot container. The scoped
    # scanner policy doesn't permit HeadBucket/CreateBucket anyway, so we
    # skip the backend's ensure_bucket() call here.
    await _recover_orphans()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    log.info("scanner worker ready")
    while not stop.is_set():
        scan_id = await _claim_one()
        if scan_id is None:
            try:
                await asyncio.wait_for(stop.wait(), timeout=POLL_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass
            continue
        log.info("starting scan %s", scan_id)
        try:
            await execute_scan(scan_id)
        except Exception:
            log.exception("execute_scan crashed for %s", scan_id)
        log.info("finished scan %s", scan_id)

    log.info("scanner worker stopping")


if __name__ == "__main__":
    asyncio.run(main())
