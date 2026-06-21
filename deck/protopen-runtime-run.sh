#!/usr/bin/env bash
# Launch the protoPen runtime container on the Steam Deck. Fetches secrets from
# Infisical (in-memory, like start.sh) into a tmpfs --env-file, then runs the
# rootful, --privileged container with fuse-overlayfs storage on /home and host
# device/network passthrough. Invoked by protopen-runtime.service. protopen-3t5.3.
set -euo pipefail

IMAGE="${PROTOPEN_IMAGE:-localhost/protopen-runtime:dev}"
PORT="${PROTOPEN_PORT:-7870}"
NAME="${PROTOPEN_NAME:-protopen-rt}"
STORE="${PROTOPEN_STORE:-$HOME/.local/share/rootful-podman}"
RUNROOT="${PROTOPEN_RUNROOT:-/run/rootful-podman}"
DATA="${PROTOPEN_DATA:-$HOME/.local/share/protopen-rt-data}"
ENVFILE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/protopen-runtime.env"
INFISICAL_DOMAIN="${INFISICAL_DOMAIN:-https://secrets.proto-labs.ai/api}"

mkdir -p "$DATA"

# Secrets -> tmpfs env-file (mode 600). Best-effort: without infisical/token the
# container still serves the UI/API; agent turns need a gateway key. Strip the
# dotenv quotes infisical emits (podman --env-file keeps them verbatim otherwise).
umask 077
: > "$ENVFILE"
if command -v infisical >/dev/null 2>&1; then
    ARGS="--domain $INFISICAL_DOMAIN --env ${INFISICAL_ENV:-prod} --format dotenv --silent"
    [ -n "${INFISICAL_TOKEN:-}" ] && ARGS="$ARGS --token $INFISICAL_TOKEN"
    infisical export $ARGS > "$ENVFILE" 2>/dev/null || true
    sed -i -E 's/^([A-Za-z_][A-Za-z0-9_]*)="(.*)"$/\1=\2/' "$ENVFILE" || true
    sed -i -E "s/^([A-Za-z_][A-Za-z0-9_]*)='(.*)'\$/\1=\2/" "$ENVFILE" || true
fi
[ -n "${OPENAI_API_KEY:-}" ] && echo "OPENAI_API_KEY=$OPENAI_API_KEY" >> "$ENVFILE"

exec sudo podman \
    --root "$STORE" --runroot "$RUNROOT" \
    --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs \
    run --rm --replace --name "$NAME" \
    --privileged --network host \
    --env-file "$ENVFILE" \
    -e PROTOPEN_PORT="$PORT" \
    -v "$DATA":/sandbox \
    -v /dev/bus/usb:/dev/bus/usb \
    "$IMAGE"
