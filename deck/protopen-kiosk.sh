#!/usr/bin/env bash
# pwnDeck — Game Mode kiosk launcher.
# Opens the operator console fullscreen in a Chromium kiosk. Added to Steam as a
# Non-Steam game (steamos-add-to-steam) so it launches from Game Mode with Steam
# Input. Tracker: protopen-3t5.2.
#
# Waits for the backend with curl (no browser CORS issues — a file:// splash can't
# fetch http://localhost, so that approach stranded the kiosk), then opens Chromium
# directly at the app. Override the target with PROTOPEN_URL.
#
# The URL pins `?shell=handheld`: the console picks its shell from TOUCH capability
# (`hover:none`+`pointer:coarse`), which is right in Game Mode but misreports as a
# desktop pointer when the kiosk runs on the Plasma desktop (or with a paired
# mouse), stranding the Deck on the dense desktop rail. The Deck is always the
# chat-first "wide phone", so force that shell regardless of pointer. See
# docs/plans/2026-07-22-chat-first-deck-ui.md + lib/useIsHandheld.ts.
set -u

URL="${PROTOPEN_URL:-http://localhost:7870/app/?shell=handheld}"
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
