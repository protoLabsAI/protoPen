---
name: ## Steam Deck SSH & protoPen
description: "## Steam Deck SSH & protoPen Server Guide

### Connection
- **Host alias:** `steamdeck` (via Tailscale SSH)
- **User:**..."
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
- LiteLLM/OpenAI key pulled from Infisical at startup via `start.sh`:
  ```
  infisical export --domain https://secrets.proto-labs.ai/api \
    --projectId f0e3382b-611c-4964-8b57-89d0db4976be \
    --env staging --format dotenv --silent
  ```
- Key is extracted from `LITELLM_MASTER_KEY` field and exported as `OPENAI_API_KEY`

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
