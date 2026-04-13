# Rabbit Hole MCP Integration

protoPen ships security intelligence (advisories, exploits, threat analysis) to the [rabbit-hole.io](https://rabbit-hole.io) knowledge graph via a direct HTTP bridge.

## Overview

The `rabbit_hole_bridge` tool converts protoPen data into rabbit-hole bundles (entities + relationships) and ingests them via the rabbit-hole REST API. No MCP transport is needed -- it is plain HTTP.

## Configuration

Set the following environment variables in your `docker-compose.yml` or `.env`:

| Variable | Description | Default |
|---|---|---|
| `RABBIT_HOLE_URL` | Base URL of the rabbit-hole API | `http://host.docker.internal:3399` |
| `MCP_AUTH_TOKEN` | Authentication token for the rabbit-hole API | _(none)_ |

The bridge is only registered when `RABBIT_HOLE_URL` is set. If unset, the tool is skipped at startup.

## Starting the Rabbit Hole Server

On the host machine (or wherever rabbit-hole runs):

```bash
cd /path/to/rabbit-hole
npm start
# Listening on http://localhost:3399
```

If running inside Docker on the same host as protoPen, the default `http://host.docker.internal:3399` should work.

## Passing the Auth Token

```bash
export MCP_AUTH_TOKEN="your-rabbit-hole-token"
docker compose up -d researcher
```

Or add it to your `.env` file:

```
MCP_AUTH_TOKEN=your-rabbit-hole-token
```

## Available Tool Actions

The `rabbit_hole_bridge` tool supports the following actions:

| Action | Description |
|---|---|
| `ingest_advisory` | Convert a KnowledgeStore advisory into a bundle and ingest |
| `ingest_exploit` | Ingest an exploit as entities + relationships |
| `ingest_text` | Ingest free-form text (threat intel, digests, summaries) |
| `search_graph` | Search the knowledge graph for existing entities |

## Verifying Connectivity

Check that protoPen can reach rabbit-hole:

```bash
# From inside the container
docker exec protopen curl -s http://host.docker.internal:3399/health
```

Or ask the agent:

```
Search the rabbit-hole knowledge graph for "transformer"
```

If the bridge is working, you will get search results or an empty set -- not a connection error.

## Firewall Notes

::: warning
If the rabbit-hole server is on a different machine or behind a firewall, ensure port `3399` (or your custom port) is reachable from the Docker container. The `extra_hosts` entry in `docker-compose.yml` maps `host.docker.internal` to the host gateway, which only works for services on the same host.
:::

For cross-machine setups, set `RABBIT_HOLE_URL` to the machine's Tailscale IP or DNS name:

```
RABBIT_HOLE_URL=http://ava:3399
```

## Subagent Usage

The Threat Scanner, Vuln Analyst, and Intel Reporter subagents all have access to `rabbit_hole_bridge`:

- **Threat Scanner** checks the graph before scanning to avoid duplicate work (`search_graph`)
- **Vuln Analyst** ingests advisories and threat intel after analysis (`ingest_advisory`, `ingest_text`)
- **Intel Reporter** ships digests to the graph after publishing (`ingest_text`)
