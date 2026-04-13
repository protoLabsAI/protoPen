---
name: Steam Deck SSH & protoPen
description: "Steam Deck SSH connection, protoPen server details, Infisical service token auth (INFISICAL_TOKEN via systemd override), protoPen project f7d3c43d prod env, systemd user service management."
type: reference
---

## Steam Deck SSH & protoPen Server Guide

### Connection
- **Host alias:** `steamdeck` (via Tailscale SSH)
- **User:** `deck`
- **Command:** `ssh deck@steamdeck`

### protoPen Location
- **Repo:** `/home/deck/protoPen`
- **Python venv:** `/home/deck/protoPen/.venv`
- **Data dir:** `/home/deck/protoPen/data` (knowledge, audit, papers, lab subdirs)

### Secrets
- All secrets pulled from Infisical at startup via `start.sh` using `INFISICAL_TOKEN` service token auth
- Infisical project: **protoPen** (`f7d3c43d-be5e-4a05-ac4c-c69d1e09d6c7`), **prod** environment
- `start.sh` exports ALL Infisical secrets into the process environment (not just `LITELLM_MASTER_KEY`)
- `LITELLM_MASTER_KEY` is also aliased to `OPENAI_API_KEY`
- Service token is injected via systemd override:
  `~/.config/systemd/user/protopen.service.d/infisical.conf` (`Environment=INFISICAL_TOKEN=...`)

### systemd User Service
- **Service file:** `~/.config/systemd/user/protopen.service`
- **Start:** `systemctl --user start protopen`
- **Stop:** `systemctl --user stop protopen`
- **Restart:** `systemctl --user restart protopen`
- **Status:** `systemctl --user status protopen --no-pager`
- **Logs:** `journalctl --user -u protopen --no-pager -n 50`
- **Also:** `/tmp/protopen.log` (stdout/stderr from start.sh)
- Auto-restarts on failure (`Restart=on-failure`, `RestartSec=5`)

### Server Details
- **Port:** 7870 (HTTP, 0.0.0.0)
- **Framework:** Uvicorn + FastAPI + Gradio UI
- **Endpoints:** `/docs` (Swagger), `/chat` (Gradio UI), various API routes

### Important SSH Gotchas
- Tailscale SSH kills child processes on disconnect — `nohup`/`setsid` do NOT survive
- **Always use the systemd user service** to start/manage the server, never raw background processes
- `pgrep` results over Tailscale SSH include the SSH handler process itself in matches — filter carefully

### Deploying Code Changes
1. `ssh deck@steamdeck "cd ~/protoPen && git pull"`
2. `ssh deck@steamdeck "systemctl --user restart protopen"`
3. Verify: `ssh deck@steamdeck "systemctl --user status protopen --no-pager"`
