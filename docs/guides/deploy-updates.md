# Deploy Updates

Concise procedure for deploying code changes to the Steam Deck.

## Prerequisites

- SSH access to the Steam Deck (`steamdeck` hostname or IP)
- The protoPen repo cloned at `/home/deck/dev/protoPen`
- Docker Compose running the `researcher` service

## Procedure

### 1. Push from your workstation

```bash
git push origin main
```

### 2. SSH into the Deck and pull

```bash
ssh deck@steamdeck
cd /home/deck/dev/protoPen
git pull origin main
```

### 3. Rebuild and restart

```bash
docker compose up --build -d researcher
```

For the lab profile (GPU-enabled):

```bash
docker compose --profile lab up --build -d researcher-lab
```

### 4. Verify

Check the container logs for a clean startup:

```bash
docker logs protoresearcher --tail 30
```

You should see:

```
[researcher] Agent backend: langgraph
[sessions] Persistent checkpointer: /sandbox/knowledge/sessions.db
[sitrep] Startup probe injected into system prompt
[researcher] LangGraph agent initialized (model: claude-sonnet-4-6)
[metrics] Prometheus metrics initialized
```

Hit the health endpoint:

```bash
curl http://localhost:7872/
```

Confirm the chat UI loads at `http://steamdeck:7872`.

::: tip
If only config files changed (under `config/`), you can restart without rebuilding since config is bind-mounted:

```bash
docker compose restart researcher
```
:::

## Rollback

If something breaks, revert to the previous commit and restart:

```bash
git revert HEAD
docker compose up --build -d researcher
```
