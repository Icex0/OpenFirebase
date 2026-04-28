"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-04-21

"""
from __future__ import annotations

import fastapi_users_db_sqlalchemy.generics
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user",
        sa.Column("id", fastapi_users_db_sqlalchemy.generics.GUID(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("hashed_password", sa.String(length=1024), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_email", "user", ["email"], unique=True)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("schema_version", sa.String(length=16), nullable=True),
        sa.Column("tool_version", sa.String(length=32), nullable=True),
        sa.Column("raw_document", sa.JSON(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_user_id", "scans", ["user_id"])
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table(
        "scan_projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", sa.String(length=255), nullable=False),
        sa.Column("package_names", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_projects_scan_id", "scan_projects", ["scan_id"])
    op.create_index("ix_scan_projects_project_id", "scan_projects", ["project_id"])

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_pk", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("service", sa.String(length=32), nullable=False),
        sa.Column("probe", sa.String(length=8), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("unauth_status", sa.String(length=8), nullable=False),
        sa.Column("unauth_security", sa.String(length=48), nullable=False),
        sa.Column("unauth_verdict", sa.String(length=24), nullable=False),
        sa.Column("unauth_message", sa.Text(), nullable=True),
        sa.Column("auth_status", sa.String(length=8), nullable=True),
        sa.Column("auth_security", sa.String(length=48), nullable=True),
        sa.Column("auth_verdict", sa.String(length=24), nullable=True),
        sa.Column("auth_message", sa.Text(), nullable=True),
        sa.Column("resource", sa.JSON(), nullable=True),
        sa.Column("raw", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["project_pk"], ["scan_projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_project_pk", "findings", ["project_pk"])
    op.create_index("ix_findings_service", "findings", ["service"])
    op.create_index("ix_findings_probe", "findings", ["probe"])
    op.create_index("ix_findings_unauth_verdict", "findings", ["unauth_verdict"])
    op.create_index("ix_findings_auth_verdict", "findings", ["auth_verdict"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("scan_projects")
    op.drop_table("scans")
    op.drop_index("ix_user_email", table_name="user")
    op.drop_table("user")
