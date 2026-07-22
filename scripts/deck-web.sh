#!/usr/bin/env bash
# Fast frontend deploy to the Steam Deck — build the console + rsync it to the
# host dist the runtime container bind-mounts, no image rebuild.
#
# WHY THIS EXISTS: the runtime image bakes a fresh `apps/web/dist`, but the Deck's
# run script also bind-mounts a host dist (`$WEBDIST`) over it for fast iteration.
# If that host dist goes stale it silently shadows the fresh baked build — which
# once froze the console UI for a month. This script keeps it fresh in seconds and
# verifies the deployed bundle, so a frontend change never needs the ~15-min image
# rebuild during active UI work. See docs/guides/deploy-updates.md.
#
# Usage:  scripts/deck-web.sh
# Env:    DECK_HOST   ssh target        (default deck@100.98.241.57)
#         DECK_WEBDIST remote dist path (default /home/deck/protoPen/apps/web/dist)
#         DECK_URL    base for verify   (default http://100.98.241.57:7870)
#         SKIP_BUILD=1 to rsync an already-built dist
set -euo pipefail

DECK_HOST="${DECK_HOST:-deck@100.98.241.57}"
DECK_WEBDIST="${DECK_WEBDIST:-/home/deck/protoPen/apps/web/dist}"
DECK_URL="${DECK_URL:-http://100.98.241.57:7870}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT/apps/web"

if [ "${SKIP_BUILD:-}" != "1" ]; then
  echo "==> building console (npm run build)…"
  npm run build
fi
[ -f dist/index.html ] || { echo "!! dist/index.html missing — build failed?"; exit 1; }

echo "==> rsyncing dist → ${DECK_HOST}:${DECK_WEBDIST}"
# One-time: the checkout dist may be root-owned from an old on-Deck build.
ssh "$DECK_HOST" "sudo chown -R \$(id -un):\$(id -gn) '${DECK_WEBDIST}' 2>/dev/null || true"
rsync -rlpt --delete dist/ "${DECK_HOST}:${DECK_WEBDIST}/"

# The bind mount reflects host changes live; no container restart needed.
echo "==> verifying served bundle…"
css="$(curl -fsS -m 10 "${DECK_URL}/app/" | grep -oE '/app/assets/index-[A-Za-z0-9_-]+\.css' | head -1)"
if [ -z "$css" ]; then echo "!! could not read /app/ — is the service up?"; exit 1; fi
local_css="$(basename "$(ls dist/assets/index-*.css | head -1)")"
served_css="$(basename "$css")"
echo "   local:  $local_css"
echo "   served: $served_css"
if [ "$local_css" = "$served_css" ]; then
  echo "==> OK — the Deck is serving the freshly built console."
else
  echo "!! served bundle ($served_css) != local build ($local_css) — the mount may be off or a restart is needed."
  exit 1
fi
