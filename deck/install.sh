#!/usr/bin/env bash
# One-command install of the protoPen runtime on a Steam Deck. Tracker: protopen-3t5.3.
#
# What it sets up (all in /home — nothing in /etc, so no atomic-update keep-list
# entry is needed; it survives SteamOS OS updates on its own):
#   - rootful podman storage on /home + fuse-overlayfs (the default /var is 230 MB)
#   - the runtime image (pulled from GHCR, or built locally with PROTOPEN_BUILD=1)
#   - a systemd --user unit that runs the rootful --privileged container at boot
#   - the Game Mode kiosk launcher
#
# Idempotent. Run as the `deck` user (NOT root). Secrets reuse the existing
# Infisical token drop-in if present; otherwise pass OPENAI_API_KEY.
set -euo pipefail
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SRC_DIR/.." && pwd)"

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
EXISTING_TOKEN="$UNIT_DIR/protopen.service.d/infisical.conf"
if [ -f "$EXISTING_TOKEN" ]; then
    install -Dm600 "$EXISTING_TOKEN" "$UNIT_DIR/protopen-runtime.service.d/infisical.conf"
    echo "==> reused INFISICAL_TOKEN from the existing protopen.service drop-in"
else
    echo "WARN: no Infisical token drop-in. Create $UNIT_DIR/protopen-runtime.service.d/infisical.conf"
    echo "      with: [Service]\\nEnvironment=\"INFISICAL_TOKEN=...\"  — or pass OPENAI_API_KEY."
fi

# 5) lingering so the --user service runs at boot without login
loginctl enable-linger "$USER" 2>/dev/null || sudo loginctl enable-linger "$USER" 2>/dev/null || true
systemctl --user daemon-reload

cat <<EOF

Installed. The runtime is NOT started yet (so it can't fight the bare-metal
protopen.service for :$PORT). To switch over:

  systemctl --user disable --now protopen.service          # free :$PORT
  systemctl --user enable  --now protopen-runtime.service   # start the container

Kiosk (run in the Deck's Desktop session, confirm the Steam dialog):
  steamos-add-to-steam ~/.local/share/applications/protopen.desktop
Then reboot into Game Mode and launch "protoPen".
EOF
