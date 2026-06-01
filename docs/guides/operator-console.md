# Operator Console

The operator console is a webview UI for driving protoPen — chat, browsing
captured target intel, unified search, manual subagent / workflow / playbook
runs, runtime status, the audit trail, and a live engagement monitor. It's served
by the protoPen server at **`/app`** (e.g. `http://localhost:7870/app/` locally,
or `http://steamdeck:7870/app/` over Tailscale on the Deck) and is built
automatically on startup.

> Note: `/app` is the console. The server's `/` is a separate legacy PWA shell —
> don't use it to check the console.

## Login

When `PROTOPEN_API_KEY` (or `RESEARCHER_API_KEY`) is set, the console is gated:
on first load it asks for the operator key and sends it as an `x-api-key` header
on every request. The key is stored in the browser and a `401` re-opens the login
gate. When no key is configured (local dev), the console is open.

## Layout

The shell is a topbar, a left rail of **groups**, the active surface, a right
panel, and a bottom utility bar.

- **Topbar** — brand on the left; on the right a single **health dot** (worst-of:
  setup / graph / event-stream / status; green = ready). Hover it for the full
  breakdown in a popover; click it to refresh.
- **Left rail** — four groups; clicking one shows its surface, which carries its
  own **tab bar** for the views within it (below).
- **Bottom utility bar** — a toggle to hide/show the right panel. The right panel
  is also **drag-resizable** by its left edge (width persists).

### Rail groups & their tabs

| Group | Tabs | What they do |
|---|---|---|
| **Chat** | Conversation · Activity | Converse with the agent over the A2A streaming endpoint (multiple sessions as tabs; double-click a tab to rename, ✕ to delete with a confirm). **Activity** is the durable agent-initiated thread (badge counts unread). |
| **Intel** | Targets · Search · Knowledge · Engagements | **Targets**: browse discovered hosts (ports, services, findings, redacted creds). **Search**: unified search across hosts, captured findings, and the knowledge store. **Knowledge**: table-filtered hybrid search (vector + BM25) over `cves`/`exploits`/`advisories`/`threat_intel`/`topics`/`digests`. **Engagements**: past engagement history with severity rollups. |
| **Agents** | Subagents · Workflows · Playbooks | **Subagents**: launch one (Single/Batch), live-tracked with status/duration/cancel. **Workflows**: run a declarative subagent recipe (ADR 0002). **Playbooks**: browse + fire the 23 declarative tool-chain recipes — see [Playbooks](../reference/playbooks.md). |
| **System** | Status · Audit · Schedule | **Status**: model/provider/identity, knowledge path, goal mode, middleware toggles, skills count, registered subagents. **Audit**: the tool-execution trail (filter All/OK/Failed, per-tool). **Schedule**: scheduled jobs. |

### Right panel (project-scoped)

Keyed to a **project path** (a host folder, e.g. `/home/deck/protoPen`) entered at
the top — set it and load to populate Notes + Beads. Toggle which tab shows:

| Tab | What it does |
|---|---|
| **Notes** | Per-project notes workspace (tabs, agent read/write permissions), autosaved. Delete asks to confirm. |
| **Beads** | The project's beads issue board — create, start/close, delete (with confirm), grouped by status. Requires the `br` CLI on the server. |
| **Engagement** | Live monitor of the active engagement — phase, mode, severity counts, findings that expand. Polls every 5s; a **report** action reads/regenerates `report.md`. |

## Theme

The console uses the Pilot Protocol terminal skin — green-on-black, monospace,
sharp corners, a faint grid field. Panels bound to the viewport and scroll
internally rather than overflowing the page.

## Under the hood

The console is a React app (`apps/web`) talking to the FastAPI routes registered
by `operator_api` (see the [Operator Console API](../reference/api-endpoints.md#operator-console-api)).
The bundle is built on startup by `start.sh` (native) or the Dockerfile
(container) when `apps/web/dist` is missing.
