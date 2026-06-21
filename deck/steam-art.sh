#!/usr/bin/env bash
# pwnDeck — generate + install Steam library art for the Game Mode shortcut.
#
# Codifies what used to be ad-hoc /tmp scripts: render the three grid assets from
# a source poster and drop them into Steam's grid dir, keyed to the pwnDeck
# shortcut's AppID. Run this ON THE DECK, in Desktop mode, AFTER you've added the
# kiosk to Steam (steamos-add-to-steam) — Steam must have minted the shortcut's
# AppID first.  [needs on-Deck validation]
#
#   deck/steam-art.sh                         # auto-discover AppID + grid dir
#   PWNDECK_ART_SRC=/path/to/poster.png deck/steam-art.sh
#   PWNDECK_APPID=2858097465 deck/steam-art.sh # override if discovery fails
#
# Requires ImageMagick (`magick` or `convert`). The portrait keeps the WHOLE
# poster (padded, not cropped); hero + wide are cover-cropped.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SRC_DIR/.." && pwd)"
SRC="${PWNDECK_ART_SRC:-$REPO_DIR/docs/public/og-image.png}"
PAD="${PWNDECK_ART_PAD:-#0b0f0d}" # poster padding color (app terminal-black)

IM="$(command -v magick || command -v convert || true)"
[ -n "$IM" ] || {
    echo "ImageMagick not found (need 'magick' or 'convert'). On the Deck: flatpak or pacman install it." >&2
    exit 1
}
[ -f "$SRC" ] || {
    echo "source poster not found: $SRC (set PWNDECK_ART_SRC)" >&2
    exit 1
}

# 1) locate the Steam userdata grid dir
STEAM_ROOT=""
for c in "$HOME/.steam/steam" "$HOME/.local/share/Steam" "$HOME/.var/app/com.valvesoftware.Steam/.local/share/Steam"; do
    [ -d "$c/userdata" ] && STEAM_ROOT="$c" && break
done
[ -n "$STEAM_ROOT" ] || {
    echo "Steam userdata not found — is Steam installed for this user?" >&2
    exit 1
}
USERDATA="$(find "$STEAM_ROOT/userdata" -maxdepth 1 -mindepth 1 -type d | head -1)"
GRID="${PWNDECK_GRID:-$USERDATA/config/grid}"
SHORTCUTS="$USERDATA/config/shortcuts.vdf"
mkdir -p "$GRID"

# 2) resolve the shortcut AppID (grid art filenames are keyed to it)
APPID="${PWNDECK_APPID:-}"
if [ -z "$APPID" ] && [ -f "$SHORTCUTS" ]; then
    APPID="$(python3 - "$SHORTCUTS" <<'PY' || true
import sys
try:
    import vdf
except ImportError:
    sys.exit(0)  # caller falls back to PWNDECK_APPID
with open(sys.argv[1], "rb") as f:
    data = vdf.binary_loads(f.read())
for entry in (data.get("shortcuts") or {}).values():
    name = (entry.get("AppName") or entry.get("appname") or "")
    if name.lower() in ("pwndeck", "protopen"):
        appid = entry.get("appid")
        if appid is not None:
            print(appid & 0xFFFFFFFF)  # unsigned, as used in grid filenames
        break
PY
)"
fi
[ -n "$APPID" ] || {
    echo "Could not resolve the pwnDeck AppID (install python 'vdf', or pass PWNDECK_APPID=…)." >&2
    echo "Find it in Steam → pwnDeck → Properties, or via the grid dir filenames." >&2
    exit 1
}

echo "==> source=$SRC  appid=$APPID  grid=$GRID"

# 3) render + install. cover = fill-and-crop; contain = whole image, padded.
cover() { "$IM" "$SRC" -resize "${1}^" -gravity center -extent "$1" "$2"; }
contain() { "$IM" "$SRC" -resize "$1" -background "$PAD" -gravity center -extent "$1" "$2"; }

cover 1920x620 "$GRID/${APPID}_hero.png" # page hero banner
cover 920x430 "$GRID/${APPID}.png"       # wide capsule
contain 600x900 "$GRID/${APPID}p.png"    # portrait library tile (keep the poster)

echo "==> installed pwnDeck art: ${APPID}_hero.png, ${APPID}.png, ${APPID}p.png"
echo "    Restart Steam (pkill -x steam) to see it."
