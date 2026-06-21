#!/usr/bin/env bash
# protoPen — Game Mode kiosk launcher.
# Opens the operator console fullscreen in a Chromium kiosk. Added to Steam as a
# Non-Steam game (steamos-add-to-steam) so it launches from Game Mode with Steam
# Input. Tracker: protopen-3t5.2.
#
# Backend: points at the live protoPen (protopen.service, :7870) by default.
# Override with PROTOPEN_URL to target the container runtime (:7871) once that
# becomes the boot runtime.
set -u

URL="${PROTOPEN_URL:-http://localhost:7870/app/}"
PROFILE="${PROTOPEN_KIOSK_PROFILE:-$HOME/.protopen-kiosk-profile}"

# Wait for the backend to answer before opening the UI (protopen.service may
# still be starting right after a Game Mode boot).
for _ in $(seq 1 90); do
    curl -sf -o /dev/null --max-time 2 "$URL" && break
    sleep 1
done

mkdir -p "$PROFILE"
exec flatpak run org.chromium.Chromium \
    --kiosk --app="$URL" \
    --user-data-dir="$PROFILE" \
    --no-first-run --no-default-browser-check \
    --disable-features=Translate \
    --ozone-platform-hint=auto
