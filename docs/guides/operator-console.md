# Operator Console

The operator console is a webview UI for driving protoPen — a **companion
presence + a running engagement**, not a dense tool list. It's served by the
protoPen server at **`/app`** (e.g. `http://localhost:7870/app/` locally, or
`http://steamdeck:7870/app/` over Tailscale on the Deck) and is built
automatically on startup.

> Note: `/app` is the console. The server's `/` is a separate legacy PWA shell —
> don't use it to check the console.

## Login

When `PROTOPEN_API_KEY` (or `RESEARCHER_API_KEY`) is set, the console is gated:
on first load it asks for the operator key and sends it as an `x-api-key` header
on every request. The key is stored in the browser and a `401` re-opens the login
gate. When no key is configured (local dev), the console is open.

## Layout

The shell is a topbar, a left rail of **companion nouns**, the active surface, a
right panel, and a bottom utility bar. The IA is **autonomous-first**: you scope
an engagement and glance/steer, with a capability catalog underneath as the
opt-in manual layer.

- **Topbar** — brand on the left; a compact **companion presence** strip in the
  middle (state + live engagement mode/target/findings); a single **health dot**
  on the right (worst-of: setup / graph / event-stream / status; green = ready).
  Hover the dot for the full breakdown; click it to refresh.
- **Left rail** — six rails; clicking one shows its surface, which carries its
  own **tab bar** for the views within it (below). A pulsing **dot on the Home
  rail** means a chat turn is streaming in the background while you're elsewhere.
- **Bottom utility bar** — a toggle to hide/show the right panel. The right panel
  is also **drag-resizable** by its left edge (width persists).

### Rails & their tabs

| Rail | Tabs | What they do |
|---|---|---|
| **Home / Companion** | _(presence hero + chat)_ | The spine. A glanceable presence hero — companion state (idle / working / waiting-on-you / offline), what it's doing now, a **needs-you** card when a turn parks on a HITL request (routes you to the waiting session), and a recent-findings ticker — above the **chat steering channel** (multi-session; double-click a tab to rename, ✕ to delete). |
| **Engagement** | Engagement · Goals · Playbooks · History | **Engagement**: the engagement as a controllable object — scope a target, set the `passive`/`active`/`redteam` mode ceiling, **start**, watch live progress (mode, findings), **end**. **Goals**: the autonomy loop (set with `/goal` in chat). **Playbooks**: browse + fire declarative tool-chain recipes — see [Playbooks](../reference/playbooks.md). **History**: past engagements with severity rollups. |
| **Findings** | Targets · Search · Knowledge | **Targets**: discovered hosts (ports, services, findings, redacted creds). **Search**: unified search across hosts, captured findings, and the knowledge store. **Knowledge**: table-filtered hybrid search (vector + BM25) over `cves`/`exploits`/`advisories`/`threat_intel`/`topics`/`digests`. |
| **Activity** | _(thread)_ | The durable agent-initiated thread (scheduled fires, agent-initiated messages). Its own rail; the rail button badges unread. |
| **Capabilities** | Catalog · Skills · Workflows · Subagents | The opt-in manual layer. **Catalog**: a friendly, searchable, category-grouped menu of what protoPen can *do* (the live tool registry), each with an **Ask agent** action that hands it to the chat steering channel. **Skills**: learned SKILL.md procedures. **Workflows**: run a declarative subagent recipe (ADR 0002). **Subagents**: launch one (Single/Batch), live-tracked with status/duration/cancel. |
| **Terminal** | _(tabbed shells)_ | A real PTY-backed terminal (xterm.js) for running tools directly when the agent's loop isn't the fit. Multiple shells as tabs; each survives tab switches and rail navigation (a running command keeps going while you glance elsewhere). Operator-key gated over a WebSocket (`/ws/terminal`). |
| **System** | Status · Audit · Schedule | **Status**: model/provider/identity, knowledge path, goal mode, middleware toggles, skills count, registered subagents. **Audit**: the tool-execution trail (filter All/OK/Failed, per-tool). **Schedule**: scheduled jobs. |

### Chat — always streaming

The chat steering channel on **Home** keeps running while you move around the app:

- **Survives navigation.** `ChatSurface` stays mounted (hidden) when you switch
  rails, so an in-flight turn keeps streaming into the store in the background —
  navigate to Findings/Engagement/Capabilities and back and the conversation is
  exactly as you left it, still progressing. The Home rail shows a pulsing dot
  while a turn streams off-tab.
- **Token-by-token.** Answers fill the bubble live as the model writes (the LLM
  streams; the server forwards each delta as an incremental frame).
- **Self-heals after a reload.** Each turn carries its A2A task id; if the stream
  is interrupted (refresh, network blip), the console reconciles the message
  against the server's durable task on load and finalizes with the real answer
  instead of spinning.
- **Subagent tools nest.** When the agent delegates via the `task` tool, the
  subagent's internal tool calls render as nested cards under the delegation.

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
The chat rides the **A2A streaming endpoint** (`/a2a`), not the plain chat SSE.
The bundle is built on startup by `start.sh` (native) or the Dockerfile
(container) when `apps/web/dist` is missing — note that a frontend change on a
host with an existing `dist` needs a forced rebuild (`rm -rf apps/web/dist`)
before restart.
