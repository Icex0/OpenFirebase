"""scan options, stage, logs

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-21

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("stage", sa.String(length=16), nullable=False, server_default="queued"),
    )
    op.create_index("ix_scans_stage", "scans", ["stage"])
    op.add_column("scans", sa.Column("options", sa.JSON(), nullable=True))

    op.add_column(
        "scan_projects",
        sa.Column("extracted_items", sa.JSON(), nullable=True),
    )

    op.create_table(
        "scan_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("stream", sa.String(length=8), nullable=False),
        sa.Column("line", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_logs_scan_id", "scan_logs", ["scan_id"])
    op.create_index("ix_scan_logs_seq", "scan_logs", ["seq"])
    op.create_index(
        "ix_scan_logs_scan_seq", "scan_logs", ["scan_id", "seq"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_scan_logs_scan_seq", table_name="scan_logs")
    op.drop_index("ix_scan_logs_seq", table_name="scan_logs")
    op.drop_index("ix_scan_logs_scan_id", table_name="scan_logs")
    op.drop_table("scan_logs")
    op.drop_column("scan_projects", "extracted_items")
    op.drop_column("scans", "options")
    op.drop_index("ix_scans_stage", table_name="scans")
    op.drop_column("scans", "stage")
