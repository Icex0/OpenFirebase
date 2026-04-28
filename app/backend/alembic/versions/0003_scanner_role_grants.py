"""scanner role grants

Locks the ``scanner_user`` role (created by the postgres init script) down
to exactly the privileges the scanner worker needs:

  * ``scans``:          SELECT + UPDATE (backend creates rows; scanner claims
                        them via SELECT ... FOR UPDATE and flips status /
                        stage fields).
  * ``scan_projects``:  full CRUD (scanner re-imports project rows each run).
  * ``findings``:       full CRUD (ditto).
  * ``scan_logs``:      SELECT + INSERT (append-only log stream).

Explicitly revokes any access to ``"user"`` and ``alembic_version`` so a
scanner compromise can't read password hashes or tamper with migration
state. No DDL, no ``CREATE EXTENSION``, no ``COPY … FROM PROGRAM``
(``NOSUPERUSER`` on the role already denies those).

Idempotent: the ``DO`` block is a no-op when the role doesn't exist (e.g.
first bring-up on an existing DB where the init script was skipped) and
re-applies cleanly on every ``alembic upgrade head``.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-23

"""
from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_user') THEN
                RAISE NOTICE 'scanner_user role not present; skipping grants';
                RETURN;
            END IF;

            EXECUTE 'GRANT USAGE ON SCHEMA public TO scanner_user';

            EXECUTE 'GRANT SELECT, UPDATE ON TABLE scans TO scanner_user';
            EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE scan_projects TO scanner_user';
            EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE findings TO scanner_user';
            EXECUTE 'GRANT SELECT, INSERT ON TABLE scan_logs TO scanner_user';

            EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO scanner_user';

            -- Belt-and-braces: even if a future migration grants PUBLIC on
            -- these tables, the scanner role is explicitly denied.
            EXECUTE 'REVOKE ALL ON TABLE "user" FROM scanner_user';
            EXECUTE 'REVOKE ALL ON TABLE alembic_version FROM scanner_user';
        END
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanner_user') THEN
                RETURN;
            END IF;
            EXECUTE 'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM scanner_user';
            EXECUTE 'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM scanner_user';
            EXECUTE 'REVOKE USAGE ON SCHEMA public FROM scanner_user';
        END
        $$;
    """)
