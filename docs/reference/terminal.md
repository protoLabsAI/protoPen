# Integrated Terminal

The console's **Terminal** rail is a real PTY-backed shell (xterm.js) for running
tools directly when the agent's loop isn't the right fit. It is the only
WebSocket on the server; everything else is REST/SSE.

## Endpoint

`GET ws(s)://<host>:7870/ws/terminal` — upgraded to a WebSocket. Not part of the
OpenAPI schema (so it doesn't appear in [API Endpoints](./api-endpoints.md)).

### Authentication

Gated by the same operator key as the REST API (`PROTOPEN_API_KEY` /
`RESEARCHER_API_KEY`). Browser WebSockets can't set headers, so the key rides the
`key` query param: `…/ws/terminal?key=<operator-key>`. A wrong/missing key when a
key is configured closes the socket with code `1008` before accept. When no key
is configured (local dev), the socket is open like the rest of the console.

### Wire protocol

JSON text frames:

| Direction | Frame |
|---|---|
| client → server | `{"type":"input","data": "<keystrokes>"}` |
| client → server | `{"type":"resize","cols": <int>,"rows": <int>}` |
| client → server | `{"type":"clear"}` (wipes the server scrollback; ⌘/Ctrl+K) |
| client → server | `{"type":"ping"}` |
| server → client | `{"type":"data","data": "<output>"}` |
| server → client | `{"type":"exit","code": <int>}` |
| server → client | `{"type":"pong"}` |

## Behavior

- **Shell** — `$SHELL`, else `bash` / `zsh` / `sh`, started as a session leader in
  a pseudo-terminal. `cwd` is `SANDBOX_DIR` if set, else `$HOME`.
- **Tabs** — multiple shells as tabs; each stays mounted (hidden) across tab
  switches, and the surface stays mounted across rail navigation, so a running
  command keeps going while you glance elsewhere.
- **Sizing** — the PTY size tracks the browser viewport (`TIOCSWINSZ`), so
  full-screen TUIs and line wrapping render correctly.
- **Theme** — matches the Pilot Protocol terminal skin.

### Hotkeys

Local convenience keys; everything else passes through to the shell. Mac uses ⌘;
other platforms use Ctrl (with Shift for copy/paste so `Ctrl+C` stays SIGINT).

| Key (Mac / other) | Action |
|---|---|
| `⌘K` / `Ctrl+K` | Clear the terminal (also wipes the server scrollback) |
| `⌘C` / `Ctrl+Shift+C` | Copy selection |
| `⌘V` / `Ctrl+Shift+V` | Paste |
| `⌘A` (Mac) | Select all |
| `Ctrl+C` | SIGINT (unchanged — passes through to the shell) |

## Security

A live interactive shell is a real capability — it runs commands in the server's
environment with the server's privileges. In the hardened container the rootfs is
read-only and capabilities are dropped (`NET_RAW` only); on the Steam Deck it runs
as the native `deck` user. It is operator-key gated and **on by default**; gate
the console behind the operator key on any reachable deployment.

## Implementation

- Backend: `server/terminal.py` (`register_terminal_ws`), wired in
  `server/app.py:build_app`. Python stdlib `pty` + an async pipe; uvicorn serves
  the WebSocket via the `websockets` dependency.
- Frontend: `apps/web/src/terminal/TerminalSurface.tsx` (xterm.js + fit/web-links
  addons).
- See the [Operator Console guide](../guides/operator-console.md) for the rail in
  context.
