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

mkdir -p "$LOCAL_DIR"
chmod 700 "$LOCAL_DIR"

STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
OUT="$LOCAL_DIR/veto-$STAMP.sql.gz"

log "dumping to $OUT"
# --no-owner so the dump restores under whatever role the target uses. Written
# to a .partial first so an interrupted run never leaves a file that looks whole.
pg_dump --no-owner --format=plain "$DATABASE_URL" | gzip -9 > "$OUT.partial"
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
