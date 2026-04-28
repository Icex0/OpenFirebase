#!/bin/sh
# Runs once, on first initialisation of the postgres data volume (the
# standard /docker-entrypoint-initdb.d hook). Creates the scoped role used
# by the scanner worker so the scanner never holds the superuser creds.
#
# Permission grants (what tables it can touch) live in an alembic migration
# so they're version-controlled and apply consistently across upgrades. The
# role needs to exist before that migration runs — this script handles
# that for fresh deploys; for existing deploys, run:
#
#   docker compose exec postgres \
#     psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
#          -v pw="'<password>'" -c "CREATE ROLE scanner_user LOGIN \
#          PASSWORD :pw NOSUPERUSER NOCREATEDB NOCREATEROLE \
#          NOREPLICATION NOBYPASSRLS;"

set -eu

if [ -z "${SCANNER_DB_PASSWORD:-}" ]; then
    echo "[postgres-init] SCANNER_DB_PASSWORD not set; skipping scanner role creation" >&2
    exit 0
fi

# psql's :'var' quoting safely escapes the password regardless of contents.
# (Must be piped via stdin — `psql -c` is parsed server-side and does not
#  expand psql variables.)
psql -v ON_ERROR_STOP=1 \
     -v pw="$SCANNER_DB_PASSWORD" \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE ROLE scanner_user LOGIN PASSWORD :'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EOSQL

echo "[postgres-init] scanner_user role ready"
