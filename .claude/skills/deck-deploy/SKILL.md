---
name: deck-deploy
description: SSH into the live Steam Deck and get it onto the latest protoPen build. Use when the user says "deploy to the deck", "update the deck", "make sure the deck is on latest", "ssh into the deck", "push this to the deck", or wants to check/verify what version the Deck is running. Encodes the connection facts, the containerized run model, and the frontend-fast vs full-image-rebuild deploy paths so this flow never has to be re-derived.
---

# Deck deploy

Operator runbook for deploying protoPen to the live Steam Deck. Follow this instead
of rediscovering the run model each time.

## 0. Connect (the hostname is a trap)

- **Live target: `ssh deck@100.98.241.57`.** The tailnet hostname `steamdeck`
  is **STALE — it times out.** Always use the IP.
- `hostname` isn't installed on SteamOS; use `uname -a` / `cat /etc/hostname`.

## 1. Run model (why the obvious checks lie)

protoPen runs as a **rootful podman container `protopen-rt`**, managed by the
**`protopen-runtime.service` systemd *user* unit** (lingering, boots without login,
lives in /home so it survives atomic OS updates). Image
`ghcr.io/protolabsai/protopen-runtime:latest`, port **7870**.

Two things that waste time if you don't know them:

- **`sudo podman ps` shows NOTHING.** The rootful store is a custom graphroot on
  /home. You must pass the flags every time:
  ```bash
  sudo podman --root ~/.local/share/rootful-podman --runroot /run/rootful-podman \
    --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs \
    ps            # ...images / inspect / pull / logs, etc.
  ```
- **`systemctl --user status protopen` is the DEAD old unit** (bare-metal venv model,
  pivoted away — `disabled/inactive`). The live one is **`protopen-runtime.service`**.
  Who's really on 7870: `sudo ss -ltnp | grep 7870`.

Layout: data volume `~/.local/share/protopen-rt-data → /sandbox`; launcher
`~/.local/bin/protopen-runtime-run.sh`; secrets via Infisical at container start.

## 2. Which path? Frontend is baked-but-shadowed

- **Frontend** (`apps/web/*`): served from a **host bind-mount
  `~/protoPen/apps/web/dist`** that shadows the image's baked copy. A stale host dist
  silently froze the UI for a month once. Deploy in seconds, no image rebuild:
  ```bash
  scripts/deck-web.sh          # build console + rsync dist + verify served bundle
  ```
- **Backend / tools / config / model / a2a** (anything not under `apps/web`): **BAKED
  into the runtime image.** The image is built **only on a `deck-image-v*` tag or a
  manual dispatch of `deck-runtime-image.yml` — never on a normal push.** So these
  fixes reach the Deck only via a new image → §3.

## 3. Full deploy (backend changed → new image needed)

1. **Trigger the build** from clean, synced `main`:
   ```bash
   git tag -a deck-image-v0.1.X -m "deck runtime image v0.1.X — <what's in it>"
   git push origin deck-image-v0.1.X        # → deck-runtime-image.yml builds :0.1.X + :latest
   ```
   (Or unversioned: `gh workflow run deck-runtime-image.yml`.) Build is ~5–6 min
   (BlackArch/chromium/libhackrf; heavy but cached). Watch it:
   ```bash
   gh run list --workflow=deck-runtime-image.yml --limit 1
   gh run watch <run-id> --exit-status
   ```
2. **Deploy to the Deck** once the image is green — pulls the ~5GB image, restarts
   the runtime, refreshes the frontend, and verifies:
   ```bash
   scripts/deck-deploy.sh       # pull + restart protopen-runtime + deck-web.sh + verify
   ```
   Do it by hand if you need to: pull (with the §1 flags) →
   `systemctl --user restart protopen-runtime` → `scripts/deck-web.sh`.

## 4. Verify (always)

- **a2a JSON-RPC must dispatch** — this is the canary. A stale backend returns
  `-32601 Method not found` (the #324 regression). Expect a real answer:
  ```bash
  ssh deck@100.98.241.57 'curl -s http://localhost:7870/a2a -X POST \
    -H "Content-Type: application/json" \
    -d '"'"'{"jsonrpc":"2.0","id":0,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"ping"}],"messageId":"v"},"contextId":"v"}}'"'"''
  ```
- **Running image digest changed:** `sudo podman --root … inspect protopen-rt --format '{{.Image}}'`.
- **Smoke (25 checks):** `ssh deck@100.98.241.57 'bash -s' < scripts/smoke.sh`.
- Version signal without shell: `curl -s http://localhost:7870/.well-known/agent-card.json`.

## 5. Diagnose current state fast

```bash
ssh deck@100.98.241.57 'systemctl --user status protopen-runtime --no-pager | head -15'
ssh deck@100.98.241.57 'journalctl --user -u protopen-runtime --no-pager -n 40'
```
Is the local `main`/image gap real? `git log --oneline <last deck-image-v*>..HEAD` —
and remember GHCR `:latest` may be newer than the last tag (manual dispatches push
`:latest` untagged). Compare the running digest to
`gh api /orgs/protoLabsAI/packages/container/protopen-runtime/versions`.

## Gotchas

- **Deep-suspend (S3) takes the Deck fully offline** (wifi, tailscaled, container).
  For remote ops mask sleep: `sudo systemctl mask sleep.target suspend.target
  hibernate.target hybrid-sleep.target` (re-add symlinks to
  `/etc/atomic-update.conf.d/` since /etc is wiped by OS updates). Power off manually after.
- **Tailscale SSH kills child processes on disconnect** — never `nohup`/`setsid` a
  server; always the systemd user service.
- **Corrupted session** (`tool_use ids … without tool_result`):
  `rm -f ~/.local/share/protopen-rt-data/knowledge/sessions.db* && systemctl --user restart protopen-runtime`.
- If `podman pull` 401s, the package needs auth: `sudo podman … login ghcr.io` with a PAT.
- `docs/guides/deploy-updates.md` still documents the OLD venv model in places — this
  skill is the source of truth for the container model.
