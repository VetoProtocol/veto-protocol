#!/usr/bin/env bash
#
# Nightly Postgres backup for Veto.
#
# Two things this script will not do, because both defeat the point:
#
#  1. It will not leave the only copy on the machine it protects. It writes
#     locally and then requires an off-host destination; a backup on the box is
#     not a backup.
#  2. It will not back up VAULT_MASTER_KEY. The dump without that key is inert
#     — which is exactly the property you want — and the key belongs somewhere
#     else, in someone else's custody. Storing them together turns one stolen
#     archive into every customer's mail.
#
# Usage:  BACKUP_DEST=user@host:/backups /srv/veto/deploy/backup.sh
# Cron:   15 3 * * *  BACKUP_DEST=... /srv/veto/deploy/backup.sh >> /var/log/veto-backup.log 2>&1

set -Eeuo pipefail

ENV_FILE="${ENV_FILE:-/srv/veto/.env}"
LOCAL_DIR="${LOCAL_DIR:-/var/backups/veto}"
KEEP_DAYS="${KEEP_DAYS:-14}"

log() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "FAILED: $*"; exit 1; }

trap 'die "aborted on line $LINENO"' ERR

[ -r "$ENV_FILE" ] || die "cannot read $ENV_FILE"

# Read DATABASE_URL without sourcing the file — .env holds every secret the
# system has, and none of the others belong in this process.
DATABASE_URL="$(grep -m1 '^DATABASE_URL=' "$ENV_FILE" | cut -d= -f2-)"
[ -n "${DATABASE_URL:-}" ] || die "DATABASE_URL not set in $ENV_FILE"

# The database name, for the superuser path below.
DB_NAME="$(printf '%s' "$DATABASE_URL" | sed -E 's#^.*/([^/?]+)(\?.*)?$#\1#')"
[ -n "$DB_NAME" ] || die "could not read a database name out of DATABASE_URL"

mkdir -p "$LOCAL_DIR"
chmod 700 "$LOCAL_DIR"

STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
OUT="$LOCAL_DIR/veto-$STAMP.sql.gz"

log "dumping to $OUT"
# Dumped as the superuser, not as the application role.
#
# Every tenant table is FORCE row-level security, and FORCE applies to the table
# **owner** — so `pg_dump` connecting as `veto` is refused on the first COPY:
#   ERROR: query would be affected by row-level security policy for table "agents"
# That is the isolation working; the role genuinely cannot see rows outside a
# workspace context, and a backup needs all of them. A superuser bypasses RLS,
# which is exactly the privilege separation that makes this safe to automate:
# the dump runs as root on the host, not as anything the application can reach.
#
# `ALTER TABLE ... NO FORCE ROW LEVEL SECURITY`, which the error helpfully
# suggests, would turn tenant isolation off for the owner permanently. Never do
# that to fix a backup.
#
# --no-owner so the dump restores under whatever role the target uses. Written
# to a .partial first so an interrupted run never leaves a file that looks whole.
if [ "$(id -u)" = "0" ] && id postgres >/dev/null 2>&1; then
  sudo -u postgres pg_dump --no-owner --format=plain "$DB_NAME" | gzip -9 > "$OUT.partial"
else
  # Not root: fall back to the URL and let it fail loudly rather than silently
  # producing an empty dump.
  pg_dump --no-owner --format=plain "$DATABASE_URL" | gzip -9 > "$OUT.partial"
fi
mv "$OUT.partial" "$OUT"
chmod 600 "$OUT"

# A dump that will not decompress is not a backup either. Cheap to check, and
# it catches a truncated write or a full disk the night it happens rather than
# the morning you need it.
gzip -t "$OUT" || die "dump did not verify"
log "verified $(du -h "$OUT" | cut -f1)"

if [ -n "${BACKUP_DEST:-}" ]; then
  log "copying to $BACKUP_DEST"
  # -p preserves the mode, so 600 survives the trip.
  scp -p -o BatchMode=yes "$OUT" "$BACKUP_DEST/" || die "off-host copy failed"
  log "off-host copy ok"
else
  # Deliberately loud. A silent local-only backup is worse than none, because
  # somebody will believe in it.
  log "WARNING: BACKUP_DEST is not set — this copy lives only on the machine it protects"
fi

log "pruning local copies older than $KEEP_DAYS days"
find "$LOCAL_DIR" -name 'veto-*.sql.gz' -mtime "+$KEEP_DAYS" -print -delete || true

log "done"

# Restore, for when you need it and are not in a state to work it out:
#
#   systemctl stop veto-api veto-gateway veto-dashboard
#   gunzip -c veto-<stamp>.sql.gz | psql "$DATABASE_URL"
#   pnpm --filter @veto/db migrate
#   systemctl start veto-api veto-gateway veto-dashboard
#
# Practise this before you need it. An untested restore is a hope.
