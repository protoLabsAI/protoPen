#!/usr/bin/env bash
# Keep the Deck reachable — repair the tailnet + runtime after a resume (or any
# other blip), without preventing sleep.
#
# WHY THIS EXISTS
# Deep-suspend (S3) freezes wifi, tailscaled and the runtime container, and they
# don't reliably come back on resume — which used to leave the Deck unreachable
# until someone woke it and fixed it by hand. That was "solved" on 2026-07-22 by
# masking the sleep targets, which stranded the Deck on a black screen instead:
# Game Mode blanks the panel *before* calling suspend, so a masked suspend.target
# fails with the screen already off and nothing ever resumes to turn it back on.
# Sleep is unmasked again (PR #343); this restores reachability the right way.
#
# WHY A TIMER RATHER THAN A /usr/lib/systemd/system-sleep HOOK
# The sleep-hook directory is root-owned and on the rootfs, so it needs an
# atomic-update keep-list entry to survive an OS update — the same fragility that
# produced the black screen. deck/install.sh deliberately lives entirely in
# /home, and this follows that rule: user units only, nothing to preserve.
# A short realtime timer costs nothing and fires promptly after resume anyway
# (systemd runs a realtime tick that elapsed while suspended as soon as it wakes),
# and unlike a resume-only hook it also covers wifi drops and container crashes.
#
# REPAIR, DON'T RESTART. A runtime restart costs ~70s of downtime and kills any
# in-flight turn, so each service is probed and only touched when actually broken.
# A healthy tick does nothing at all and logs nothing.

set -uo pipefail

PORT="${PROTOPEN_PORT:-7870}"
TS_BIN="$HOME/.local/bin/tailscale"
TS_SOCK="$HOME/.local/share/tailscale/tailscaled.sock"
RT_UNIT="protopen-runtime.service"
TS_UNIT="tailscaled.service"
# A cold runtime needs ~70s before it serves. Don't call a booting service broken.
RT_BOOT_GRACE_S=180
STATE_DIR="${XDG_RUNTIME_DIR:-/tmp}/protopen-watchdog"

mkdir -p "$STATE_DIR"
log() { printf '%s\n' "$*"; }  # stdout → journald via the unit

# ── probes ───────────────────────────────────────────────────────────────────

ts_healthy() {
    [ -x "$TS_BIN" ] || return 0  # tailscale not installed here — nothing to keep up
    "$TS_BIN" --socket="$TS_SOCK" status --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
online = (d.get("Self") or {}).get("Online")
sys.exit(0 if d.get("BackendState") == "Running" and online else 1)
' 2>/dev/null
}

rt_serving() {
    curl -fsS --max-time 5 -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null
}

unit_enabled() { systemctl --user is-enabled --quiet "$1" 2>/dev/null; }
unit_active() { systemctl --user is-active --quiet "$1" 2>/dev/null; }

# Seconds since the unit last entered the active state (0 if unknown/inactive).
unit_uptime_s() {
    local ts now
    ts=$(systemctl --user show "$1" -p ActiveEnterTimestampMonotonic --value 2>/dev/null)
    [ -n "$ts" ] && [ "$ts" != "0" ] || { echo 0; return; }
    now=$(awk '{printf "%d", $1 * 1000000}' /proc/uptime)
    echo $(((now - ts) / 1000000))
}

# ── repair ───────────────────────────────────────────────────────────────────

# The tailnet is the remote-access path, so repair it first and give it a moment
# to settle before judging the runtime (which is reachable locally regardless).
repair_tailscale() {
    unit_enabled "$TS_UNIT" || return 0  # operator disabled it deliberately
    if ts_healthy; then
        rm -f "$STATE_DIR/ts-down"
        return 0
    fi
    # One grace tick: a resume often reconnects on its own within seconds, and
    # restarting tailscaled mid-reconnect is slower than just waiting.
    if [ ! -f "$STATE_DIR/ts-down" ]; then
        : >"$STATE_DIR/ts-down"
        log "[watchdog] tailnet down — waiting one tick before restarting $TS_UNIT"
        return 0
    fi
    log "[watchdog] tailnet still down — restarting $TS_UNIT"
    systemctl --user restart "$TS_UNIT" || log "[watchdog] restart of $TS_UNIT failed"
    rm -f "$STATE_DIR/ts-down"
}

repair_runtime() {
    unit_enabled "$RT_UNIT" || return 0  # operator disabled it deliberately

    if ! unit_active "$RT_UNIT"; then
        log "[watchdog] $RT_UNIT not active — starting it"
        systemctl --user start "$RT_UNIT" || log "[watchdog] start of $RT_UNIT failed"
        rm -f "$STATE_DIR/rt-down"
        return 0
    fi

    if rt_serving; then
        rm -f "$STATE_DIR/rt-down"
        return 0
    fi

    # Active but not answering. Could just be booting — leave it alone until the
    # boot grace has passed, else the watchdog restarts it forever and it never
    # finishes starting.
    local up
    up=$(unit_uptime_s "$RT_UNIT")
    if [ "$up" -lt "$RT_BOOT_GRACE_S" ]; then
        log "[watchdog] $RT_UNIT active but not serving yet (${up}s < ${RT_BOOT_GRACE_S}s grace) — waiting"
        return 0
    fi

    if [ ! -f "$STATE_DIR/rt-down" ]; then
        : >"$STATE_DIR/rt-down"
        log "[watchdog] $RT_UNIT active but not serving on :$PORT — waiting one tick"
        return 0
    fi
    log "[watchdog] $RT_UNIT still not serving on :$PORT — restarting"
    systemctl --user restart "$RT_UNIT" || log "[watchdog] restart of $RT_UNIT failed"
    rm -f "$STATE_DIR/rt-down"
}

repair_tailscale
repair_runtime
exit 0
