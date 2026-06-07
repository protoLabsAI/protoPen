# Handoff: Companion UI, Streaming Chat & Integrated Terminal

**Date**: 2026-06-07
**Handoff Number**: 004

---

## Overview/Summary

This run took the operator console from a four-rail "operator console" to the
**autonomous-first companion UI** from the north-star vision, then made the chat
**always-streaming** and added an **integrated terminal**. Everything below is
shipped, released, and deployed to the Deck. Released across **v2.0.29 → v2.0.33**.

What remains is the terminal's planned follow-ups (split panes, reconnect, theme
picker) — already filed in the tracker.

## Background/Context

- **North star:** `docs/plans/2026-06-05-companion-ui-vision.md` — protoPen as a
  self-driving pentest companion (presence + running engagement), autonomous-first
  with a capability catalog as the opt-in manual layer.
- **Console transport:** the React console (`apps/web`, served at `/app`) drives
  chat over the **A2A streaming endpoint** (`/a2a`), not the plain `/api/chat`
  SSE. Operator-key gated (`PROTOPEN_API_KEY` / `RESEARCHER_API_KEY`).
- **Deck deploy is git-pull + systemd**, NOT the Docker image (`docker-compose`
  maps `7872`; the live service is `7870`). `start.sh` only builds
  `apps/web/dist` when it's **missing**, so a frontend change needs
  `rm -rf apps/web/dist && npm run web:build` before `systemctl --user restart
  protopen`. See `docs/guides/deploy-updates.md`.

## Current State

Completed (all shipped + on the Deck):
- [x] **Companion IA restructure** (`protopen-cym`, closed) — rails are now
      Home · Engagement · Findings · Activity · Capabilities · Terminal · System.
      Slices: rails regroup (#187), Home presence (#189), Engagement-as-object
      (#190), Capabilities catalog `protopen-1vd` (#192).
- [x] **Always-streaming chat** — navigation persistence (#196), token-by-token
      (#197), interrupted-stream reconcile via `GetTask` (#198).
- [x] **Subagent tools render** — verified already-working (callback propagation
      through `subagent.ainvoke` → `astream_events`); #196 makes the cards persist.
- [x] **OpenAPI drift guard** (#202) — CI now checks the committed spec against
      the live app (`scripts/check_openapi_spec.py`), not just page-vs-spec.
- [x] **Docs refresh** (#200) — operator-console guide, API reference + spec,
      README, guides index.
- [x] **Integrated terminal MVP** (#203, v2.0.33) — own Terminal rail, tabbed
      real shells over `/ws/terminal`.

Remaining (filed in `br`):
- [ ] `protopen-3dd` (P2) — Terminal: recursive split panes (Alt+D/Alt+S + spatial nav)
- [ ] `protopen-330` (P3) — Terminal: reconnect + scrollback persistence
- [ ] `protopen-3j9` (P3) — Terminal: theme picker + font zoom

## Technical Approach

- **Always-mounted surfaces** — chat and terminal render unconditionally with an
  `active` prop (`display:none` off-rail) so an in-flight turn / running command
  survives rail navigation. Terminal additionally lazy-mounts on first open.
- **Terminal backend** is the server's **first WebSocket** — protomaker's
  `node-pty` is Node-only, so the PTY half is a Python stdlib reimplementation
  (`pty.openpty` + an async pipe). Auth via `?key=` (browser WS can't set headers).
- **Companion-state sharing** — `useCompanionState`/`STATE_LABEL` exported from
  `CompanionStatus.tsx` so the topbar strip and the Home hero can't drift.

## Key Files and Documentation

| File | Purpose |
|------|---------|
| `apps/web/src/app/App.tsx` | Rails, surface enum, always-mounted chat + terminal |
| `apps/web/src/app/HomeSurface.tsx` | Companion presence hero |
| `apps/web/src/targets/EngagementSurface.tsx` | Engagement-as-object control surface |
| `apps/web/src/targets/CapabilitiesSurface.tsx` | Capabilities catalog (B-subtext) |
| `apps/web/src/terminal/TerminalSurface.tsx` | xterm.js terminal (tabs) |
| `server/terminal.py` | PTY ↔ WebSocket bridge (`/ws/terminal`) |
| `operator_api/capabilities.py` | `GET /api/tools` categorized tool catalog |
| `scripts/check_openapi_spec.py` | CI spec-vs-app drift guard |
| `docs/plans/2026-06-06-companion-ia-restructure-slices.md` | The IA slice plan |
| `docs/guides/operator-console.md`, `docs/reference/terminal.md` | Console + terminal docs |

## Acceptance Criteria

For the terminal follow-ups (the remaining work):
- [ ] Split a terminal tab horizontally/vertically; panes resize; spatial nav works
- [ ] A terminal survives a **browser reload** (reconnect + scrollback replay)
- [ ] Theme picker + per-pane font zoom, defaulting to the Pilot Protocol skin

## Open Questions/Considerations

- **Terminal security surface** — a live shell runs with the server's privileges.
  It's operator-key gated and **on by default** (agreed scope). If a deployment
  ever exposes the console without a key, the terminal is open too; consider a
  `TERMINAL_ENABLED` flag if that ever becomes a risk (protomaker has one).
- **`/sandbox` hardcodes** — `agent_init.py` / `knowledge/store.py` /
  `graph/goals/store.py` default several paths to `/sandbox/...`; this blocks a
  local `--dump-openapi` off the Deck (read-only `/`). The CI drift guard works
  around it by creating `/sandbox` best-effort. Honoring `SANDBOX_DIR` everywhere
  would be a clean cleanup.
- **No web e2e harness** — protoPen has no Playwright/web unit tests; the web
  build (`tsc`) is the only frontend gate. protomaker's terminal e2e specs could
  seed one if desired.

## Next Steps

1. **Terminal split panes** (`protopen-3dd`) — port protomaker's recursive pane
   tree (`{type:'terminal'|'split', direction, panels[]}`) into
   `TerminalSurface.tsx`; backend (`/ws/terminal`) is unchanged. Refs:
   `/Users/kj/dev/protomaker/apps/ui/src/components/views/terminal-view.tsx` +
   `store/terminal-store.ts`.
2. Then reconnect/scrollback (`protopen-330`) and theming (`protopen-3j9`).
3. **Process:** branch per feature → web build + `ruff`/`pytest` green → PR (CI:
   CodeRabbit often leaves a stale `CHANGES_REQUESTED` and skips re-review; after
   fixing, dismiss the stale review via `gh api -X PUT
   repos/.../pulls/N/reviews/<id>/dismissals -f event=DISMISS`, then merge) →
   Prepare Release auto-opens the bump PR → merge bump + tag `vX.Y.Z` → deploy to
   the Deck (git pull + `rm -rf apps/web/dist && npm run web:build` + restart) →
   `ssh deck@steamdeck 'bash -s' < scripts/smoke.sh`.

See the agent memory at `~/.claude/projects/-Users-kj-dev-protoPen/memory/` —
`project_companion_ia_restructure`, `project_chat_streaming_adoption`,
`project_integrated_terminal` — for deeper notes and the gotchas hit along the way.
