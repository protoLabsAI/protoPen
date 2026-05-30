# Operator Console

The operator console is a webview UI for driving protoPen — chat, knowledge
search, manual subagent launches with live monitoring, runtime status, the audit
trail, and a live engagement monitor. It's served by the protoPen server at
**`/app`** (e.g. `http://localhost:7870/app/` locally, or `http://steamdeck:7870/app/`
over Tailscale on the Deck) and is built automatically on startup.

## Login

When `PROTOPEN_API_KEY` (or `RESEARCHER_API_KEY`) is set, the console is gated:
on first load it asks for the operator key and sends it as an `x-api-key` header
on every request. The key is stored in the browser and a `401` re-opens the login
gate. When no key is configured (local dev), the console is open.

## Layout

A left rail switches the main **surface**; a right panel holds project-scoped
tools (Notes / Beads / Engagement).

### Surfaces (left rail)

| Surface | What it does |
|---|---|
| **Chat** | Converse with the agent over the A2A streaming endpoint; multiple sessions in tabs. |
| **Knowledge** | Hybrid search (vector + BM25, RRF) over the threat-intel store. Filter by source table (`cves`, `exploits`, `advisories`, `threat_intel`, `topics`, `digests`); ranked hits show source id, table, preview, and score. |
| **Subagents** | Launch a subagent — **Single** (async, tracked) or **Batch** (concurrent). The **Tracked Agents** list shows each run's status (`running`/`done`/`error`/`cancelled`) + duration, expands to its output, and lets you **cancel** running agents. Polls while any agent is active. |
| **Runtime** | Model, provider, identity, knowledge path, goal mode, middleware toggles, and the registered subagents. |
| **Audit** | The tool-execution trail (newest first) from `audit.jsonl` — status pill, tool, duration, timestamp, result summary, session/trace. Filter by All / OK / Failed and per-tool. |

### Right panel

| Tab | What it does |
|---|---|
| **Notes** | Per-project notes workspace (tabs, agent read/write permissions), autosaved. |
| **Beads** | The project's beads issue board — create, start/close, delete, grouped by status. |
| **Engagement** | Live monitor of the active engagement — phase, mode, severity counts, and findings that expand to show detail. Polls every 5s while open; a **report** action reads (or regenerates) the engagement `report.md`. |

## Theme

The console uses the Pilot Protocol terminal skin — green-on-black, monospace,
sharp corners, a faint grid field. Panels bound to the viewport and scroll
internally rather than overflowing the page.

## Under the hood

The console is a React app (`apps/web`) talking to the FastAPI routes registered
by `operator_api` (see the [Operator Console API](../reference/api-endpoints.md#operator-console-api)).
The bundle is built on startup by `start.sh` (native) or the Dockerfile
(container) when `apps/web/dist` is missing.
