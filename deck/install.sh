#!/usr/bin/env bash
# One-command install of the pwnDeck (protoPen) runtime on a Steam Deck.
#
# Run deck/bootstrap.sh FIRST (the privileged host prep). This script lives
# entirely in /home, so it survives SteamOS atomic updates on its own:
#   - rootful podman storage on /home + fuse-overlayfs (the default /var is 230 MB)
#   - the runtime image (pulled from GHCR, or built locally with PROTOPEN_BUILD=1)
#   - a systemd --user unit that runs the rootful --privileged container at boot,
#     enabled + started here (the container is THE runtime — no bare-metal step)
#   - the Game Mode kiosk launcher
#
# Idempotent. Run as the `deck` user (NOT root). No API key needed up front — the
# first-run setup wizard collects it in-browser. For the fleet gateway instead,
# pass --with-infisical (reuses an Infisical token drop-in). Tracker: protopen-3t5.3.
set -euo pipefail
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SRC_DIR/.." && pwd)"

WITH_INFISICAL=0
for arg in "$@"; do
    case "$arg" in
        --with-infisical) WITH_INFISICAL=1 ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

IMAGE="${PROTOPEN_IMAGE:-ghcr.io/protolabsai/protopen-runtime:latest}"
PORT="${PROTOPEN_PORT:-7870}"
STORE="$HOME/.local/share/rootful-podman"
RUNROOT="/run/rootful-podman"
DATA="$HOME/.local/share/protopen-rt-data"
UNIT_DIR="$HOME/.config/systemd/user"

echo "==> protoPen Deck install (image=$IMAGE port=$PORT)"
[ "$(id -u)" -ne 0 ] || { echo "Run as the deck user, not root."; exit 1; }
command -v podman >/dev/null || { echo "podman missing (SteamOS ships it)."; exit 1; }
command -v fuse-overlayfs >/dev/null || echo "WARN: fuse-overlayfs missing — rootful overlay may fall back."

# 1) storage + data + dirs, all on /home
mkdir -p "$STORE" "$DATA" "$HOME/.local/bin" "$UNIT_DIR/protopen-runtime.service.d" \
         "$HOME/.local/share/applications"

# 2) image — pull the published one, or build locally with PROTOPEN_BUILD=1
PODMAN_STORE=(--root "$STORE" --runroot "$RUNROOT" \
    --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs)
if [ "${PROTOPEN_BUILD:-0}" = "1" ]; then
    echo "==> building image from $REPO_DIR/deck/Containerfile (this is slow)…"
    sudo podman "${PODMAN_STORE[@]}" build -f "$REPO_DIR/deck/Containerfile" -t "$IMAGE" "$REPO_DIR"
elif sudo podman "${PODMAN_STORE[@]}" image exists "$IMAGE"; then
    echo "==> image $IMAGE already present locally; skipping pull"
else
    echo "==> pulling $IMAGE…"
    sudo podman "${PODMAN_STORE[@]}" pull "$IMAGE"
fi

# 3) launcher (run wrapper + kiosk + desktop entry)
install -Dm755 "$SRC_DIR/protopen-runtime-run.sh" "$HOME/.local/bin/protopen-runtime-run.sh"
install -Dm755 "$SRC_DIR/protopen-kiosk.sh"        "$HOME/protopen-kiosk.sh"
install -Dm644 "$SRC_DIR/protopen.desktop"         "$HOME/.local/share/applications/protopen.desktop"

# 4) systemd --user unit + port/image drop-in (+ reuse the Infisical token drop-in)
install -Dm644 "$SRC_DIR/protopen-runtime.service" "$UNIT_DIR/protopen-runtime.service"
cat > "$UNIT_DIR/protopen-runtime.service.d/env.conf" <<EOF
[Service]
Environment=PROTOPEN_PORT=$PORT
Environment=PROTOPEN_IMAGE=$IMAGE
EOF
# Secrets: BYO by default (the setup wizard collects the key in-browser and the
# runtime persists it under /sandbox). --with-infisical opts into the fleet
# gateway by reusing an existing Infisical token drop-in.
RT_DROPIN="$UNIT_DIR/protopen-runtime.service.d/infisical.conf"
EXISTING_TOKEN="$UNIT_DIR/protopen.service.d/infisical.conf"
if [ "$WITH_INFISICAL" = "1" ] && [ -f "$EXISTING_TOKEN" ]; then
    install -Dm600 "$EXISTING_TOKEN" "$RT_DROPIN"
    echo "==> --with-infisical: reused INFISICAL_TOKEN from the existing protopen.service drop-in"
elif [ "$WITH_INFISICAL" = "1" ]; then
    echo "WARN: --with-infisical given but no token at $EXISTING_TOKEN."
    echo "      Create $RT_DROPIN with: [Service] / Environment=INFISICAL_TOKEN=...  (or use the wizard)."
else
    rm -f "$RT_DROPIN" # no stale fleet token shadowing the BYO wizard key
    echo "==> BYO key: the first-run setup wizard will collect your model + API key"
fi

# 5) retire any bare-metal protopen.service (the container is THE runtime now) so
#    it can't fight the container for :$PORT, then enable + start the container.
loginctl enable-linger "$USER" 2>/dev/null || sudo loginctl enable-linger "$USER" 2>/dev/null || true
systemctl --user daemon-reload
if systemctl --user cat protopen.service >/dev/null 2>&1; then
    echo "==> retiring the bare-metal protopen.service"
    systemctl --user disable --now protopen.service 2>/dev/null || true
fi
echo "==> enabling + (re)starting protopen-runtime.service"
systemctl --user enable protopen-runtime.service
# restart (not just enable --now): on a re-run an already-active unit must pick up
# the updated env.conf / infisical.conf and the freshly pulled image.
systemctl --user restart protopen-runtime.service

cat <<EOF

Installed and running on :$PORT — the container is the runtime, no extra step.

Game Mode kiosk (run once in the Deck's Desktop session, confirm the Steam dialog):
  steamos-add-to-steam ~/.local/share/applications/protopen.desktop
Then reboot into Game Mode and launch "pwnDeck". On first run the setup wizard
opens in-app — enter your model + API key and you're live.
EOF
