from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .models import Scan, ScanProject, ScanBundle  # noqa: F401


class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, scan: Scan) -> Scan:
        self.session.add(scan)
        await self.session.flush()
        return scan

    async def get_for_update(self, scan_id: uuid.UUID) -> Scan | None:
        """Load a scan with its projects+findings eagerly. No user filter; use
        only from trusted internal code (e.g. background worker) where the
        scan id has already been authorised upstream."""
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.projects).selectinload(ScanProject.findings))
        )
        return await self.session.scalar(stmt)

    async def get(self, scan_id: uuid.UUID, user_id: uuid.UUID) -> Scan | None:
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id, Scan.user_id == user_id)
            .options(
                selectinload(Scan.projects).selectinload(ScanProject.findings),
                selectinload(Scan.bundles),
            )
        )
        return await self.session.scalar(stmt)

    async def list_for_user(self, user_id: uuid.UUID) -> list[Scan]:
        stmt = (
            select(Scan)
            .where(Scan.user_id == user_id)
            .options(selectinload(Scan.bundles))
            .order_by(Scan.created_at.desc())
        )
        result = await self.session.scalars(stmt)
        return list(result)

    async def delete(self, scan_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        scan = await self.session.scalar(
            select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
        )
        if scan is None:
            return False
        await self.session.delete(scan)
        return True
