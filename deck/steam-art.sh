#!/usr/bin/env bash
# pwnDeck — brand the Steam shortcut: rename it to pwnDeck + install library art.
#
# Run this ON THE DECK in Desktop mode, AFTER adding the kiosk to Steam
# (steamos-add-to-steam). Dependency-free: the three grid assets are pre-rendered
# in deck/art/ (just copied — no ImageMagick), and shortcuts.vdf is read/edited by
# the bundled pure-Python steam-shortcut.py (no `vdf` pip package).
#
# Steam rewrites shortcuts.vdf on exit, so this stops Steam before editing; restart
# Steam (or reboot) afterwards to see the new name + art.
#
#   deck/steam-art.sh                 # rename to pwnDeck + install art
#   PWNDECK_APPID=2858097465 deck/steam-art.sh   # if AppID auto-detect fails
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
ART="$SRC_DIR/art"
HELPER="$SRC_DIR/steam-shortcut.py"
NEWNAME="${PWNDECK_NAME:-pwnDeck}"

for f in hero.png wide.png portrait.png; do
    [ -f "$ART/$f" ] || {
        echo "missing pre-rendered art: $ART/$f" >&2
        exit 1
    }
done

# 1) locate Steam userdata + the shortcut + grid dir
STEAM_ROOT=""
for c in "$HOME/.steam/steam" "$HOME/.local/share/Steam" "$HOME/.var/app/com.valvesoftware.Steam/.local/share/Steam"; do
    [ -d "$c/userdata" ] && STEAM_ROOT="$c" && break
done
[ -n "$STEAM_ROOT" ] || {
    echo "Steam userdata not found — is Steam installed for this user?" >&2
    exit 1
}
USERDATA="$(find "$STEAM_ROOT/userdata" -maxdepth 1 -mindepth 1 -type d | head -1)"
SHORTCUTS="$USERDATA/config/shortcuts.vdf"
GRID="${PWNDECK_GRID:-$USERDATA/config/grid}"
[ -f "$SHORTCUTS" ] || {
    echo "no shortcuts.vdf yet — add the kiosk to Steam first:" >&2
    echo "  steamos-add-to-steam ~/.local/share/applications/protopen.desktop" >&2
    exit 1
}
mkdir -p "$GRID"

# 2) Steam must be stopped, or it clobbers our edit on exit.
if pgrep -x steam >/dev/null 2>&1; then
    echo "==> stopping Steam to edit shortcuts safely…"
    pkill -TERM -x steam 2>/dev/null || true
    for _ in $(seq 1 25); do pgrep -x steam >/dev/null 2>&1 || break; sleep 1; done
fi

# 3) rename the shortcut to pwnDeck (keeps the AppID), then resolve that AppID.
python3 "$HELPER" rename "$SHORTCUTS" "$NEWNAME" || echo "==> rename skipped (not found or already $NEWNAME)"
APPID="${PWNDECK_APPID:-$(python3 "$HELPER" appid "$SHORTCUTS" "$NEWNAME" || true)}"
[ -n "$APPID" ] || {
    echo "Could not resolve the pwnDeck AppID — pass PWNDECK_APPID=… (Steam → pwnDeck → Properties)." >&2
    exit 1
}

# 4) install the pre-rendered grid art, keyed to the AppID.
cp -f "$ART/hero.png" "$GRID/${APPID}_hero.png"      # page hero banner (1920x620)
cp -f "$ART/wide.png" "$GRID/${APPID}.png"           # wide capsule (920x430)
cp -f "$ART/portrait.png" "$GRID/${APPID}p.png"      # portrait library tile (600x900)

echo "==> done: shortcut '$NEWNAME', art installed (appid=$APPID)"
echo "    grid: $GRID"
echo "    Restart Steam (or reboot into Game Mode) to see it."
