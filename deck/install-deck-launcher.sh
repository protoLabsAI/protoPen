#!/usr/bin/env bash
# Install the protoPen Game Mode kiosk launcher on the Steam Deck.
# Tracker: protopen-3t5.2.  Run as the `deck` user (NOT root).
set -euo pipefail
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

# 1) Browser for the kiosk — Chromium flatpak (--user, lives in /home; the system
#    flatpak dir is on the tiny /var partition).
if ! flatpak info --user org.chromium.Chromium >/dev/null 2>&1; then
    flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
    flatpak install --user -y flathub org.chromium.Chromium
fi

# 2) Launcher + desktop entry.
install -Dm755 "$SRC_DIR/protopen-kiosk.sh" "$HOME/protopen-kiosk.sh"
install -Dm644 "$SRC_DIR/protopen.desktop" "$HOME/.local/share/applications/protopen.desktop"

echo "Installed:"
echo "  ~/protopen-kiosk.sh"
echo "  ~/.local/share/applications/protopen.desktop"
echo
echo "3) Register it as a Non-Steam game (run in the Deck's Desktop session;"
echo "   confirm the Steam dialog that pops):"
echo "     steamos-add-to-steam ~/.local/share/applications/protopen.desktop"
echo
echo "4) (optional) Brand the Steam library art for the new shortcut:"
echo "     deck/steam-art.sh"
echo
echo "Then reboot into Game Mode and launch 'pwnDeck' from your library."
echo "(Backend defaults to the live :7870 server; set PROTOPEN_URL to retarget.)"
