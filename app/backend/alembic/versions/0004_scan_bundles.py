"""scan_bundles junction table

Switches uploaded APK/IPA storage from a scan-id-keyed prefix
(``apks/{scan_id}/<filename>``) to a content-addressed scheme
(``bundles/{sha256}``) with a junction table mapping each scan to one or
more bundle hashes. Rescans become a junction-row copy instead of a full
byte copy, and identical APKs uploaded across multiple scans are stored
exactly once.

Schema-only — existing ``apks/{scan_id}/`` objects in MinIO are not
migrated. They become orphans; users wanting to rescan them must
re-upload.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-23
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_bundles",
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id", "filename"),
    )
    op.create_index(
        "ix_scan_bundles_sha256", "scan_bundles", ["sha256"]
    )

    # Grant the scoped scanner role read access on the new table so the
    # worker can resolve bundle references at scan time.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_user') THEN
                EXECUTE 'GRANT SELECT ON TABLE scan_bundles TO scanner_user';
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.drop_index("ix_scan_bundles_sha256", table_name="scan_bundles")
    op.drop_table("scan_bundles")
