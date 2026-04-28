"""Per-scan pub/sub for live log / status events, backed by Postgres
``LISTEN/NOTIFY``.

The publisher (the scanner worker) runs in a different container from the
subscribers (the backend's SSE handlers), so we can't use an in-process
queue. Postgres is already a hard dependency, so we route events through
``pg_notify`` on a single shared channel — small payload (≤8000 bytes) carries
``{scan_id, event}`` and per-process bookkeeping fans them out to in-memory
subscribers.

Subscribers get a bounded ``asyncio.Queue``. If the queue fills (a slow
client), events are dropped for that subscriber only — we never block the
scan worker on a slow SSE consumer.

History is served from the database (``scan_logs`` table); this pub/sub is
purely for the *live* tail. New subscribers should first replay historical
logs, then subscribe.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict
from typing import Any

import asyncpg

from ..config import get_settings

log = logging.getLogger(__name__)

_CHANNEL = "openfirebase_scan"
_QUEUE_MAX = 512


def _asyncpg_dsn() -> str:
    """asyncpg wants ``postgresql://`` — strip the SQLAlchemy driver suffix."""
    url = get_settings().database_url
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


class LogBus:
    """Postgres-NOTIFY-backed pub/sub.

    Two connections per process, both lazily opened:
      * publisher: short-running ``SELECT pg_notify(...)`` calls, serialised
        through a lock so a single asyncpg connection is enough.
      * listener: holds an ``add_listener`` callback that fans payloads out
        to the in-memory subscriber queues.

    Either side can be unused (the worker only publishes, the backend only
    subscribes) — connections aren't opened until the first call.
    """

    def __init__(self) -> None:
        self._subs: dict[uuid.UUID, set[asyncio.Queue]] = defaultdict(set)
        self._sub_lock = asyncio.Lock()

        self._listener_conn: asyncpg.Connection | None = None
        self._listener_lock = asyncio.Lock()

        self._pub_conn: asyncpg.Connection | None = None
        self._pub_lock = asyncio.Lock()

    # ---------- publish ----------

    async def publish(self, scan_id: uuid.UUID, event: dict[str, Any]) -> None:
        payload = json.dumps(
            {"scan_id": str(scan_id), "event": event}, separators=(",", ":")
        )
        async with self._pub_lock:
            try:
                if self._pub_conn is None or self._pub_conn.is_closed():
                    self._pub_conn = await asyncpg.connect(_asyncpg_dsn())
                await self._pub_conn.execute(
                    "SELECT pg_notify($1, $2)", _CHANNEL, payload
                )
            except Exception:
                # Drop the connection; next publish will reconnect.
                if self._pub_conn is not None:
                    try:
                        await self._pub_conn.close()
                    except Exception:
                        pass
                self._pub_conn = None
                log.exception("pg_notify failed for scan %s", scan_id)

    # ---------- subscribe ----------

    async def subscribe(self, scan_id: uuid.UUID) -> asyncio.Queue:
        await self.start_listener()
        q: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
        async with self._sub_lock:
            self._subs[scan_id].add(q)
        return q

    async def unsubscribe(self, scan_id: uuid.UUID, q: asyncio.Queue) -> None:
        async with self._sub_lock:
            subs = self._subs.get(scan_id)
            if subs and q in subs:
                subs.discard(q)
                if not subs:
                    self._subs.pop(scan_id, None)

    async def start_listener(self) -> None:
        """Open the listener connection if it isn't already.

        Safe to call repeatedly; the FastAPI lifespan calls it on startup so
        a NOTIFY arriving just before the first SSE subscriber isn't lost.
        """
        async with self._listener_lock:
            if self._listener_conn is not None and not self._listener_conn.is_closed():
                return
            conn = await asyncpg.connect(_asyncpg_dsn())
            await conn.add_listener(_CHANNEL, self._on_notify)
            self._listener_conn = conn
            log.info("pubsub listener attached to channel %s", _CHANNEL)

    async def stop(self) -> None:
        async with self._listener_lock:
            if self._listener_conn is not None:
                try:
                    await self._listener_conn.close()
                except Exception:
                    pass
                self._listener_conn = None
        async with self._pub_lock:
            if self._pub_conn is not None:
                try:
                    await self._pub_conn.close()
                except Exception:
                    pass
                self._pub_conn = None

    def _on_notify(self, _conn, _pid, _channel, payload: str) -> None:
        try:
            msg = json.loads(payload)
            scan_id = uuid.UUID(msg["scan_id"])
            event = msg["event"]
        except Exception:
            log.warning("bad NOTIFY payload: %r", payload[:200])
            return
        subs = list(self._subs.get(scan_id, ()))
        for q in subs:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass


bus = LogBus()
