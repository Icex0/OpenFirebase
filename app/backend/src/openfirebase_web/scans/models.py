from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"


class ScanStage(str, enum.Enum):
    queued = "queued"
    extracting = "extracting"
    extracted = "extracted"
    scanning = "scanning"
    done = "done"
    failed = "failed"


class LogStream(str, enum.Enum):
    stdout = "stdout"
    stderr = "stderr"
    system = "system"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(
        String(16), default=ScanStatus.queued.value, index=True
    )
    stage: Mapped[str] = mapped_column(
        String(16), default=ScanStage.queued.value, index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    options: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    schema_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_document: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    projects: Mapped[list[ScanProject]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    logs: Mapped[list[ScanLog]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    bundles: Mapped[list[ScanBundle]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanBundle(Base):
    """A reference from a scan to a content-addressed bundle blob.

    The bundle bytes themselves live in MinIO at ``bundles/{sha256}`` and are
    deduplicated across scans — uploading the same APK twice (or rescanning
    one) reuses the existing object. ``filename`` preserves the *display*
    name the user picked at upload time so the UI can still show
    ``MyApp-1.2.3.apk`` even though the stored key is just the hash.
    """
    __tablename__ = "scan_bundles"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    filename: Mapped[str] = mapped_column(String(255), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column()

    scan: Mapped[Scan] = relationship(back_populates="bundles")


class ScanProject(Base):
    __tablename__ = "scan_projects"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[str] = mapped_column(String(255), index=True)
    package_names: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    extracted_items: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="projects")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_pk: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scan_projects.id", ondelete="CASCADE"), index=True
    )

    service: Mapped[str] = mapped_column(String(32), index=True)
    probe: Mapped[str] = mapped_column(String(8), index=True)
    url: Mapped[str] = mapped_column(Text)

    unauth_status: Mapped[str] = mapped_column(String(8))
    unauth_security: Mapped[str] = mapped_column(String(48))
    unauth_verdict: Mapped[str] = mapped_column(String(24), index=True)
    unauth_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    auth_status: Mapped[str | None] = mapped_column(String(8), nullable=True)
    auth_security: Mapped[str | None] = mapped_column(String(48), nullable=True)
    auth_verdict: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    auth_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    resource: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    project: Mapped[ScanProject] = relationship(back_populates="findings")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    seq: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    stream: Mapped[str] = mapped_column(String(8))
    line: Mapped[str] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="logs")
