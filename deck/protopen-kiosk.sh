#!/usr/bin/env bash
# pwnDeck — Game Mode kiosk launcher.
# Opens the operator console fullscreen in a Chromium kiosk. Added to Steam as a
# Non-Steam game (steamos-add-to-steam) so it launches from Game Mode with Steam
# Input. Tracker: protopen-3t5.2.
#
# Waits for the backend with curl (no browser CORS issues — a file:// splash can't
# fetch http://localhost, so that approach stranded the kiosk), then opens Chromium
# directly at the app. Override the target with PROTOPEN_URL.
set -u

URL="${PROTOPEN_URL:-http://localhost:7870/app/}"
PROFILE="${PROTOPEN_KIOSK_PROFILE:-$HOME/.protopen-kiosk-profile}"

# Wait for the backend (generous for a cold image start; usually already up via the
# lingering systemd unit) so Chromium never opens to a connection error.
for _ in $(seq 1 150); do
    curl -sf -o /dev/null --max-time 2 "$URL" && break
    sleep 2
done

mkdir -p "$PROFILE"
exec flatpak run org.chromium.Chromium \
    --kiosk --app="$URL" \
    --user-data-dir="$PROFILE" \
    --no-first-run --no-default-browser-check \
    --disable-features=Translate \
    --ozone-platform-hint=auto
