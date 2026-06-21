#!/usr/bin/env bash
# pwnDeck host bootstrap — idempotent privileged prep for the protoPen runtime.
#
# A SteamOS atomic update reimages the rootfs: it re-enables the read-only flag
# and wipes /etc (sudoers, pacman keyring) and /usr (anything pacman-installed,
# e.g. a tailscale dropped in /usr). Nothing in /home is touched. So the rule is:
#
#   run this ONCE on a fresh Deck, and AGAIN after every SteamOS update.
#
# Every step is guarded, so re-running is safe and fast. Run as the `deck` user
# (it uses sudo for the privileged bits) — NOT as root.
#
#   deck/bootstrap.sh                    # core host prep
#   deck/bootstrap.sh --with-tailscale   # + remote SSH that survives OS updates
#                                        #   (binaries + state + unit all in /home)
set -euo pipefail

WITH_TAILSCALE=0
for arg in "$@"; do
    case "$arg" in
        --with-tailscale) WITH_TAILSCALE=1 ;;
        -h | --help)
            cat <<'USAGE'
pwnDeck host bootstrap — idempotent privileged prep. Run as the `deck` user.
Re-run after every SteamOS update (an update wipes /etc + /usr; /home survives).

  deck/bootstrap.sh                    core host prep (readonly off, sudoers,
                                       pacman keyring, linger)
  deck/bootstrap.sh --with-tailscale   + remote SSH that survives OS updates
                                       (binaries + state + unit all in /home)
USAGE
            exit 0
            ;;
        *)
            echo "unknown argument: $arg (try --help)" >&2
            exit 1
            ;;
    esac
done

[ "$(id -u)" -ne 0 ] || {
    echo "Run as the deck user (it uses sudo), not root." >&2
    exit 1
}

# Authoritative login name (don't trust a possibly-unset/spoofed $USER) — reused
# for the sudoers grant, linger, and the tailscale operator.
WHO="$(id -un)"

TS_VERSION="${TAILSCALE_VERSION:-1.80.2}"
TS_DIR="$HOME/.local/share/tailscale"
TS_BIN_DIR="$HOME/.local/bin"

# Install tailscale entirely under /home so an OS update can't wipe it (the whole
# reason SSH broke before). Userspace networking + Tailscale SSH avoids any kernel
# TUN-module dependency; tailscaled runs via sudo (root) from a --user unit so its
# state + socket live in /home and the node stays authenticated across updates.
bootstrap_tailscale() {
    mkdir -p "$TS_DIR" "$TS_BIN_DIR"

    if [ ! -x "$TS_BIN_DIR/tailscaled" ] || [ ! -x "$TS_BIN_DIR/tailscale" ]; then
        local arch tgz url tmp
        case "$(uname -m)" in
            x86_64) arch=amd64 ;;
            aarch64) arch=arm64 ;;
            *)
                echo "unsupported arch for tailscale: $(uname -m)" >&2
                return 1
                ;;
        esac
        tgz="tailscale_${TS_VERSION}_${arch}.tgz"
        url="https://pkgs.tailscale.com/stable/${tgz}"
        tmp="$(mktemp -d)"
        echo "==> installing tailscale ${TS_VERSION} (${arch}) under /home (survives OS updates)"
        curl -fsSL "$url" -o "$tmp/$tgz"
        tar -xzf "$tmp/$tgz" -C "$tmp"
        install -Dm755 "$tmp/tailscale_${TS_VERSION}_${arch}/tailscale" "$TS_BIN_DIR/tailscale"
        install -Dm755 "$tmp/tailscale_${TS_VERSION}_${arch}/tailscaled" "$TS_BIN_DIR/tailscaled"
        rm -rf "$tmp"
    else
        echo "==> tailscale binaries already in $TS_BIN_DIR"
    fi

    local unit="$HOME/.config/systemd/user/tailscaled.service"
    mkdir -p "$(dirname "$unit")"
    cat >"$unit" <<UNIT
[Unit]
Description=Tailscale node agent (pwnDeck, /home-persistent)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/sudo $TS_BIN_DIR/tailscaled --statedir=$TS_DIR --socket=$TS_DIR/tailscaled.sock --tun=userspace-networking
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable --now tailscaled.service
    echo "==> tailscaled started (user unit)."
    if sudo "$TS_BIN_DIR/tailscale" --socket="$TS_DIR/tailscaled.sock" status >/dev/null 2>&1; then
        echo "    Already authenticated (state in $TS_DIR)."
    else
        echo "    First-time auth — run this and follow the URL:"
        echo "      sudo $TS_BIN_DIR/tailscale --socket=$TS_DIR/tailscaled.sock up --ssh --operator=$WHO"
    fi
}

echo "==> pwnDeck host bootstrap (re-run me after every SteamOS update)"

# 1) read-only rootfs OFF — so the /etc writes below actually stick.
if command -v steamos-readonly >/dev/null 2>&1; then
    if steamos-readonly status 2>/dev/null | grep -qiw enabled; then
        echo "==> disabling read-only rootfs"
        sudo steamos-readonly disable
    else
        echo "==> read-only rootfs already disabled"
    fi
fi

# 2) passwordless sudo for `deck` — install.sh's `sudo podman` and the rootful
#    runtime (and optional tailscaled) rely on it. Lives in /etc, so it's wiped
#    by an OS update and re-applied here. Validated before install so a typo
#    can't lock sudo out.
SUDOERS=/etc/sudoers.d/zz-protopen
SUDO_LINE="$WHO ALL=(ALL) NOPASSWD: ALL"
if ! sudo grep -qxF "$SUDO_LINE" "$SUDOERS" 2>/dev/null; then
    echo "==> writing $SUDOERS (passwordless sudo for $WHO)"
    TMP_SUDO="$(mktemp)"
    echo "$SUDO_LINE" >"$TMP_SUDO"
    if sudo visudo -cf "$TMP_SUDO" >/dev/null; then
        sudo install -Dm440 "$TMP_SUDO" "$SUDOERS"
    else
        echo "ERROR: refusing to install an invalid sudoers file" >&2
        rm -f "$TMP_SUDO"
        exit 1
    fi
    rm -f "$TMP_SUDO"
else
    echo "==> passwordless sudo already configured"
fi

# 3) pacman keyring — only needed if you build/install Arch packages on the host;
#    cheap to ensure, and an OS update wipes it.
if command -v pacman-key >/dev/null 2>&1 && [ ! -d /etc/pacman.d/gnupg ]; then
    echo "==> initializing pacman keyring"
    if ! { sudo pacman-key --init && sudo pacman-key --populate archlinux; }; then
        echo "WARN: pacman keyring init/populate failed — host pacman installs won't verify." >&2
    fi
fi

# 4) linger — let --user services (the runtime; optional tailscale) start at boot
#    without an interactive login. Stored in systemd state (not the rootfs), so it
#    survives updates; re-asserting it is a no-op. Linger is required for autostart,
#    so a failure is surfaced rather than swallowed.
if ! { loginctl enable-linger "$WHO" >/dev/null 2>&1 || sudo loginctl enable-linger "$WHO" >/dev/null 2>&1; }; then
    echo "WARN: could not enable linger — --user units may not start until you log in." >&2
fi

# 5) optional: an update-surviving tailscale (remote SSH).
if [ "$WITH_TAILSCALE" = "1" ]; then
    bootstrap_tailscale
fi

echo "==> host bootstrap complete"
if [ "$WITH_TAILSCALE" = "0" ]; then
    echo "    (run with --with-tailscale to add update-surviving remote SSH)"
fi
exit 0
