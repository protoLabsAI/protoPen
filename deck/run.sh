#!/usr/bin/env bash
# Run the protoPen SteamOS runtime container on the Steam Deck.
# Rootful + --privileged + host netns (required for WiFi monitor mode / raw
# sockets / SDR — proven in protopen-2n5). Storage lives on /home (the default
# /var/lib/containers is on a 230 MB partition). Tracker: protopen-3t5.1.
set -euo pipefail

STORE="${PROTOPEN_STORE:-/home/deck/.local/share/rootful-podman}"
RUNROOT="${PROTOPEN_RUNROOT:-/run/rootful-podman}"
IMAGE="${PROTOPEN_IMAGE:-protopen-runtime:dev}"
PORT="${PROTOPEN_PORT:-7871}"
NAME="${PROTOPEN_NAME:-protopen-rt}"

# Pass through the gateway key if the operator exported it (boots the agent;
# without it the server still serves the API + React console).
EXTRA=()
[ -n "${OPENAI_API_KEY:-}" ]  && EXTRA+=(-e "OPENAI_API_KEY=${OPENAI_API_KEY}")
[ -n "${OPENAI_BASE_URL:-}" ] && EXTRA+=(-e "OPENAI_BASE_URL=${OPENAI_BASE_URL}")
# Device passthrough (only what is present). NB: /dev/ttyACM0 is the Steam Deck
# controller — never pass it; the Flipper is ttyACM1.
[ -e /dev/ttyACM1 ] && EXTRA+=(--device=/dev/ttyACM1)
[ -e /dev/bus/usb ] && EXTRA+=(-v /dev/bus/usb:/dev/bus/usb)

exec sudo podman --root "$STORE" --runroot "$RUNROOT" run -d --replace \
    --name "$NAME" --privileged --network host \
    -e "PROTOPEN_PORT=${PORT}" \
    "${EXTRA[@]}" \
    "$IMAGE"
