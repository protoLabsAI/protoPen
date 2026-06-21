#!/usr/bin/env bash
# protoPen launcher — fetches secrets from Infisical at runtime, no env on disk.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Activate venv if present
if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
fi

# Create workspace directories (Docker uses /sandbox, native uses ./data)
SANDBOX="${SANDBOX_DIR:-$SCRIPT_DIR/data}"
mkdir -p "$SANDBOX/knowledge" "$SANDBOX/audit" "$SANDBOX/papers" "$SANDBOX/lab"
export SANDBOX_DIR="$SANDBOX"

# Symlink /sandbox for code that hardcodes the path (skip if already exists)
if [ ! -e /sandbox ]; then
    if [ "$(id -u)" -eq 0 ]; then
        ln -sfn "$SANDBOX" /sandbox
    else
        sudo ln -sfn "$SANDBOX" /sandbox 2>/dev/null \
            || echo "WARN: could not symlink /sandbox → $SANDBOX (knowledge store will fail)"
    fi
fi

# Fetch secrets from Infisical (in-memory only)
# Supports both service token (INFISICAL_TOKEN) and interactive login session.
INFISICAL_ARGS="--domain https://secrets.proto-labs.ai/api --env prod --format dotenv --silent"
if [ -n "${INFISICAL_TOKEN:-}" ]; then
    INFISICAL_ARGS="$INFISICAL_ARGS --token $INFISICAL_TOKEN"
fi

SECRETS="$(infisical export $INFISICAL_ARGS 2>/dev/null)" || true

if [ -z "$SECRETS" ]; then
    echo "ERROR: Failed to fetch secrets from Infisical."
    echo "Set INFISICAL_TOKEN or run: infisical login --domain https://secrets.proto-labs.ai/api"
    exit 1
fi

# Export all Infisical secrets into the environment (in-memory only)
eval "$(echo "$SECRETS" | sed "s/^/export /")"

# protoLabs gateway key → OPENAI_API_KEY (the gateway/LiteLLM api key)
export OPENAI_API_KEY="$GATEWAY_API_KEY"
# GitHub token alias
export GITHUB_TOKEN="${GH_TOKEN:-}"

echo "✓ Secrets loaded from Infisical ($(echo "$SECRETS" | wc -l | tr -d ' ') vars)"

# Use LangGraph backend pointed at ava
export AGENT_BACKEND=langgraph

# Build the React operator console (served at /app) if its bundle is missing —
# survives reboots / fresh clones without a manual build. The Deck has node/npm;
# skip silently if unavailable or on failure so the server still starts
# (mount_react_app no-ops without dist → Gradio-only, as before).
if [ ! -f apps/web/dist/index.html ] && command -v npm >/dev/null 2>&1; then
    echo "Operator console bundle missing — building apps/web…"
    if npm install --no-audit --no-fund >/dev/null 2>&1 && npm run web:build >/dev/null 2>&1; then
        echo "✓ operator console built (apps/web/dist)"
    else
        echo "WARN: operator console build failed — /app will 404 until built"
    fi
fi

# Browser tool: ensure the agent-browser CLI is available (idempotent). The
# Docker image installs it at build time; native runtimes (e.g. the Steam Deck,
# where the global npm prefix /usr is read-only on the immutable rootfs) install
# it here into a user-local prefix under $HOME that survives reboots and OS image
# updates. Always export the prefix bin onto PATH so server.py's subprocess can
# find it even when the install was done on a previous boot.
export NPM_CONFIG_PREFIX="${NPM_CONFIG_PREFIX:-$HOME/.npm-global}"
export PATH="$NPM_CONFIG_PREFIX/bin:$PATH"
if ! command -v agent-browser >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    echo "Installing agent-browser (browser tool)…"
    if npm install -g agent-browser >/dev/null 2>&1; then
        # Download the bundled Chrome. Skip --with-deps: it needs apt/root and
        # SteamOS uses pacman; the browser runs without it on the Deck.
        agent-browser install >/dev/null 2>&1 || echo "WARN: agent-browser browser download failed"
        echo "✓ agent-browser installed ($NPM_CONFIG_PREFIX/bin)"
    else
        echo "WARN: agent-browser install failed — browser tool will be unavailable"
    fi
fi

# tools/browser.py runs the browser with HOME=/tmp (small tmpfs for the profile),
# which hides the Chrome that `agent-browser install` placed under the real
# $HOME. Pin the executable explicitly so it's found regardless of HOME.
if [ -z "${AGENT_BROWSER_EXECUTABLE_PATH:-}" ]; then
    CHROME_BIN="$(find "$HOME/.agent-browser/browsers" -maxdepth 3 -name chrome -type f 2>/dev/null | head -1)"
    [ -n "$CHROME_BIN" ] && export AGENT_BROWSER_EXECUTABLE_PATH="$CHROME_BIN"
fi

# Maigret (OSINT username recon) — isolated venv so its pinned deps
# (aiohttp/requests/lxml/reportlab/…) never clash with protoPen's. The maigret
# tool resolves the binary via MAIGRET_BIN. Idempotent; the venv lives in $HOME
# so it survives reboots and OS image updates.
export MAIGRET_BIN="${MAIGRET_BIN:-$HOME/.maigret-venv/bin/maigret}"
if [ ! -x "$MAIGRET_BIN" ]; then
    echo "Installing maigret (OSINT username recon)…"
    if python3 -m venv "$HOME/.maigret-venv" >/dev/null 2>&1 \
        && "$HOME/.maigret-venv/bin/pip" install -q maigret >/dev/null 2>&1; then
        echo "✓ maigret installed ($MAIGRET_BIN)"
    else
        echo "WARN: maigret install failed — the maigret tool will be unavailable"
    fi
fi

# holehe (OSINT email→accounts recon) — isolated venv (pins httpx/trio). The
# holehe tool resolves the binary via HOLEHE_BIN. Idempotent; venv in $HOME.
export HOLEHE_BIN="${HOLEHE_BIN:-$HOME/.holehe-venv/bin/holehe}"
if [ ! -x "$HOLEHE_BIN" ]; then
    echo "Installing holehe (OSINT email recon)…"
    if python3 -m venv "$HOME/.holehe-venv" >/dev/null 2>&1 \
        && "$HOME/.holehe-venv/bin/pip" install -q holehe >/dev/null 2>&1; then
        echo "✓ holehe installed ($HOLEHE_BIN)"
    else
        echo "WARN: holehe install failed — the holehe tool will be unavailable"
    fi
fi

# SIPVicious OSS (telecom SIP enum/crack) — isolated venv. telecom_attack.py calls
# sipvicious_svmap/_svcrack/_svwar by name (PATH, with --format json), so symlink
# them into ~/.local/bin (added to PATH below). NB: this is the pip `sipvicious`
# package, not BlackArch's classic svmap/svwar/svcrack. Idempotent; venv in $HOME.
if [ ! -x "$HOME/.local/bin/sipvicious_svmap" ]; then
    echo "Installing sipvicious (SIP enum/crack)…"
    if python3 -m venv "$HOME/.sipvicious-venv" >/dev/null 2>&1 \
        && "$HOME/.sipvicious-venv/bin/pip" install -q sipvicious >/dev/null 2>&1; then
        mkdir -p "$HOME/.local/bin"
        for _b in sipvicious_svmap sipvicious_svcrack sipvicious_svwar; do
            ln -sf "$HOME/.sipvicious-venv/bin/$_b" "$HOME/.local/bin/$_b"
        done
        echo "✓ sipvicious installed (~/.local/bin)"
    else
        echo "WARN: sipvicious install failed — telecom SIP actions will be unavailable"
    fi
fi
# Ensure ~/.local/bin (sipvicious_*, phoneinfoga) is on PATH for PATH-resolved tools.
export PATH="$HOME/.local/bin:$PATH"

# PhoneInfoga (OSINT phone-number recon) — pinned release binary + checksum.
# NOTE: `go install` does NOT work for phoneinfoga v2 (its embedded web
# client/dist isn't in the module), and piping master/install to bash is
# unpinned, so we fetch a specific release asset and verify its sha256.
# Resolved via PHONEINFOGA_BIN. Idempotent. x86_64 Linux (Deck + the image).
PHONEINFOGA_VERSION="${PHONEINFOGA_VERSION:-2.11.0}"
PHONEINFOGA_SHA256="6173dfc4ec009a6fe688068bac5a250646f5a8f56409098f5edcc7e404b12a52"
export PHONEINFOGA_BIN="${PHONEINFOGA_BIN:-$HOME/.local/bin/phoneinfoga}"
if [ ! -x "$PHONEINFOGA_BIN" ]; then
    echo "Installing phoneinfoga v${PHONEINFOGA_VERSION} (OSINT phone recon)…"
    mkdir -p "$HOME/.local/bin"
    _pidir="$(mktemp -d)"
    _piurl="https://github.com/sundowndev/phoneinfoga/releases/download/v${PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz"
    if curl -sSL "$_piurl" -o "$_pidir/pi.tar.gz" \
        && echo "${PHONEINFOGA_SHA256}  $_pidir/pi.tar.gz" | sha256sum -c - >/dev/null 2>&1 \
        && tar -xzf "$_pidir/pi.tar.gz" -C "$_pidir" phoneinfoga \
        && mv "$_pidir/phoneinfoga" "$PHONEINFOGA_BIN"; then
        chmod +x "$PHONEINFOGA_BIN"
        echo "✓ phoneinfoga installed ($PHONEINFOGA_BIN)"
    else
        echo "WARN: phoneinfoga install failed (download/checksum) — the phoneinfoga tool will be unavailable"
    fi
    rm -rf "$_pidir"
fi

# Disable WiFi power-save on the active interface (best-effort). The Deck's radio
# otherwise sleeps between beacons, which adds ~80ms of latency to the first
# packet after an idle gap — felt directly as input lag in the console terminal
# and chat (measured ~85ms → ~8ms echo RTT with it off). Re-applied every start
# since it resets on reconnect/reboot. `iw set power_save` needs CAP_NET_ADMIN,
# which a systemd --user service lacks, so fall back to passwordless sudo (the
# Deck allows it). Fully non-fatal if `iw`/sudo are missing or denied.
if command -v iw >/dev/null 2>&1; then
    _wif="$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')"
    if [ -n "$_wif" ]; then
        if iw dev "$_wif" set power_save off >/dev/null 2>&1 \
            || sudo -n iw dev "$_wif" set power_save off >/dev/null 2>&1; then
            echo "✓ WiFi power-save off on $_wif (lower interactive latency)"
        else
            echo "WARN: could not disable WiFi power-save on $_wif (needs CAP_NET_ADMIN/sudo) — non-fatal"
        fi
    fi
fi

exec python -m server "$@"  # ADR 0023: server.py became the server/ package
