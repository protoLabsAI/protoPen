# Deploy Updates

Concise procedure for deploying code changes to the Steam Deck.

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
