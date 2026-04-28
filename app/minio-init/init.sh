#!/bin/sh
# Provisions the bucket and the scoped scanner user/policy. Idempotent.
set -eu

: "${S3_ACCESS_KEY:?required}"
: "${S3_SECRET_KEY:?required}"
: "${S3_BUCKET:?required}"
: "${SCANNER_S3_ACCESS_KEY:?required}"
: "${SCANNER_S3_SECRET_KEY:?required}"

mc alias set local http://minio:9000 "$S3_ACCESS_KEY" "$S3_SECRET_KEY"
mc mb --ignore-existing "local/$S3_BUCKET"

mc admin policy create local scanner-policy /policies/scanner-policy.json \
  || mc admin policy update local scanner-policy /policies/scanner-policy.json

mc admin user add local "$SCANNER_S3_ACCESS_KEY" "$SCANNER_S3_SECRET_KEY"
mc admin policy attach local scanner-policy --user "$SCANNER_S3_ACCESS_KEY" || true

echo "minio-init: scanner policy + user ready"
