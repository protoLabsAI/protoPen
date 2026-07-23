# Deploy Updates

Concise procedure for deploying code changes to the Steam Deck.

## Frontend-only changes (fast path — no image rebuild)

The runtime container bind-mounts a **host** `apps/web/dist` over its baked copy, so
console changes deploy in seconds without rebuilding the ~15-min runtime image:

```bash
scripts/deck-web.sh          # builds apps/web, rsyncs dist to the Deck, verifies the served bundle
```

The bind mount reflects host changes live (no restart). **Gotcha:** if that host dist
goes stale it silently shadows the fresh *baked* build — that once froze the console UI
for a month. `scripts/deck-web.sh` keeps it fresh and fails loudly if the served bundle
doesn't match what it just built. (Backend changes still need a full image rebuild +
`deck-runtime-image.yml` + pull/restart — the backend is baked, not mounted.)

## Keeping the Deck reachable (disable suspend)

Deep-suspend (S3) freezes **everything** — wifi, `tailscaled`, and the runtime
container — so a suspended Deck is offline in *both* Desktop and Game Mode, and any
in-flight or [headless goal drive](../reference/goals.md#headless-drives-detach--attach)
stalls. This is **not** a tailscale problem: `tailscaled` is a lingering,
boot-persistent user service that stays up across sessions. Suspend is driven by
Steam/SteamOS via `logind` → `suspend.target`.

To keep the Deck always reachable (e.g. for remote ops or a headless drive), mask
the sleep targets:

```bash
ssh deck@steamdeck 'sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target'
# verify it refuses to sleep WITHOUT actually sleeping:
ssh deck@steamdeck 'sudo systemctl start suspend.target'   # → "Unit suspend.target is masked."
```

The mask lives in `/etc`, which atomic OS updates wipe — add the four
`/etc/systemd/system/*.target` symlinks to `/etc/atomic-update.conf.d/protopen-keep.conf`
so they persist. Reverse any time with `systemctl unmask …`. Tradeoff: no
battery-saving auto-sleep, so power the Deck off manually when you're done.

## Prerequisites

- SSH or Tailscale access to the Steam Deck (`steamdeck` hostname)
- The protoPen repo cloned at `/home/deck/protoPen`
- The `protopen` systemd user service enabled

## Procedure

### 1. Push from your workstation

```bash
git push origin main
```

### 2. Deploy to the Deck

**Option A — Remote (one-liner from your workstation):**

```bash
ssh deck@steamdeck 'cd /home/deck/protoPen && git pull && systemctl --user restart protopen'
```

**Option B — Direct A2A (no SSH needed if Tailscale is up):**

After pushing, SSH in once to pull and restart, or use the A2A endpoint
to verify the current version and trigger a pull via the agent.

### 3. Verify

Smoke-test the A2A endpoint over Tailscale (preferred) or SSH:

```bash
curl -s http://steamdeck:7870/a2a \
  -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":0,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"ping"}]},"contextId":"deploy-check"}}'
```

Check systemd logs if the service is unresponsive:

```bash
ssh deck@steamdeck 'journalctl --user -u protopen.service --no-pager -n 30'
```

::: tip
Prefer `http://steamdeck:7870` over SSH tunneling for all A2A interactions.
Tailscale provides a direct, encrypted path without SSH overhead.
:::

## Clearing corrupted sessions

If the agent returns `tool_use ids were found without tool_result blocks`,
the LangGraph session checkpointer has corrupted state. Fix:

```bash
ssh deck@steamdeck 'rm -f /sandbox/knowledge/sessions.db* && systemctl --user restart protopen'
```

## Rollback

If something breaks, revert to the previous commit and restart:

```bash
ssh deck@steamdeck 'cd /home/deck/protoPen && git revert HEAD --no-edit && systemctl --user restart protopen'
```
