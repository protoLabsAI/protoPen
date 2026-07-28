#!/usr/bin/env bash
# Full backend deploy to the Steam Deck — pull the freshly-built runtime image,
# restart the containerized runtime, refresh the frontend, and verify.
#
# WHY THIS EXISTS: the backend is BAKED into ghcr.io/.../protopen-runtime and the
# image is only rebuilt on a `deck-image-v*` tag or a manual dispatch of
# deck-runtime-image.yml — NEVER on a normal push. So backend/tool/config fixes
# reach the Deck only after (1) a new image is built and (2) the Deck pulls it and
# restarts. This script is step 2. Pair it with the tag that triggers step 1.
# Frontend-only changes don't need this — use scripts/deck-web.sh (seconds, no image).
# See .claude/skills/deck-deploy/SKILL.md and docs/guides/deploy-updates.md.
#
# Usage:  scripts/deck-deploy.sh              # pull + restart + refresh web + verify
# Env:    DECK_HOST    ssh target             (default deck@100.98.241.57)
#         DECK_URL     base for verify        (default http://100.98.241.57:7870)
#         PROTOPEN_IMAGE  image ref           (default ghcr.io/protolabsai/protopen-runtime:latest)
#         SKIP_WEB=1    don't run deck-web.sh (skip the frontend refresh)
#         SKIP_SMOKE=1  don't run scripts/smoke.sh at the end
set -euo pipefail

DECK_HOST="${DECK_HOST:-deck@100.98.241.57}"
DECK_URL="${DECK_URL:-http://100.98.241.57:7870}"
IMAGE="${PROTOPEN_IMAGE:-ghcr.io/protolabsai/protopen-runtime:latest}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# The runtime uses a rootful podman with a CUSTOM graphroot on /home (survives
# atomic OS updates). Plain `sudo podman ...` sees NOTHING — always pass these.
PODMAN='sudo podman --root "$HOME/.local/share/rootful-podman" --runroot /run/rootful-podman --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs'

echo "==> [1/5] current running image on ${DECK_HOST}"
before="$(ssh "$DECK_HOST" "bash -lc '$PODMAN inspect protopen-rt --format {{.Image}} 2>/dev/null'" || echo none)"
echo "    before: ${before:0:19}"

echo "==> [2/5] pulling $IMAGE (rootful store — this is ~5GB, be patient)…"
ssh -o ServerAliveInterval=30 "$DECK_HOST" "bash -lc '$PODMAN pull \"$IMAGE\"'"

echo "==> [3/5] restarting protopen-runtime.service onto the new image…"
ssh "$DECK_HOST" "systemctl --user restart protopen-runtime"

# Gate on readiness BEFORE the frontend refresh — deck-web.sh verifies the served
# bundle, so it races the restart if the runtime hasn't rebound :7870 yet.
echo "    waiting for the runtime to bind :7870…"
up=""
for i in $(seq 1 45); do
  if ssh "$DECK_HOST" 'curl -fsS -m 5 http://localhost:7870/.well-known/agent-card.json >/dev/null 2>&1'; then up=1; break; fi
  sleep 2
done
[ -n "$up" ] && echo "    runtime is up." || echo "    !! runtime didn't answer in ~90s — continuing; checks below will show state"

echo "==> [4/5] refreshing frontend (host dist bind-mount shadows the baked one)…"
if [ "${SKIP_WEB:-}" = "1" ]; then
  echo "    SKIP_WEB=1 — skipping deck-web.sh"
else
  # Non-fatal: the backend is already deployed by this point, and the loop doesn't
  # depend on the console. A frontend build hiccup (e.g. missing tsc/deps) warns
  # and continues instead of aborting the whole deploy.
  DECK_HOST="$DECK_HOST" DECK_URL="$DECK_URL" "$ROOT/scripts/deck-web.sh" || \
    echo "    !! frontend refresh failed (tsc/deps? run 'npm ci' in apps/web, or SKIP_WEB=1) — backend is deployed; continuing"
fi

echo "==> [5/5] verifying…"
after="$(ssh "$DECK_HOST" "bash -lc '$PODMAN inspect protopen-rt --format {{.Image}} 2>/dev/null'" || echo none)"
echo "    image: ${before:0:19} -> ${after:0:19}"
[ "$before" != "$after" ] && echo "    OK — image changed" || echo "    !! image unchanged (already latest, or pull/restart no-op)"

# a2a JSON-RPC dispatch must work (regression guard for the #324 'Method not found' bug)
a2a="$(ssh "$DECK_HOST" 'curl -s -m 20 http://localhost:7870/a2a -X POST -H "Content-Type: application/json" -d '"'"'{"jsonrpc":"2.0","id":0,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"ping"}],"messageId":"deploy-verify"},"contextId":"deploy-verify"}}'"'"'' || true)"
if echo "$a2a" | grep -q '"code":-32601'; then
  echo "    !! a2a dispatch BROKEN (-32601 Method not found) — backend not on the fixed image"; exit 1
else
  echo "    OK — a2a JSON-RPC dispatch responds"
fi

if [ "${SKIP_SMOKE:-}" != "1" ] && [ -f "$ROOT/scripts/smoke.sh" ]; then
  echo "==> smoke test (scripts/smoke.sh)…"
  ssh "$DECK_HOST" 'bash -s' < "$ROOT/scripts/smoke.sh" || echo "    (smoke reported failures — review above)"
fi

echo "==> done."
