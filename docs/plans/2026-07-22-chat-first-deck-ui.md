# Chat-first Deck UI

**Status:** in progress (P0–P3 built; P2/P3 pending on-Deck validation) · **Owner:** kj · **Date:** 2026-07-22

Reshape the console into a **chat-first UI tuned for the Steam Deck screen** (1280×800,
7″ touch, gamescope/chromium kiosk). Evolves the companion-UI north star; on the handheld
it supersedes the rails-first companion IA. Informed by protoAgent's recent chat-first work
(ADR 0086 chat-first mobile shell, 0045 chat-as-slot lifetime mount, 0090 goals-drive-in-a-tab,
0020 run-from-chat) — **adapted, not ported.**

## The core principle

**The Deck is a wide phone, not a small desktop.** It is 1280px wide — *above* every
width-based mobile breakpoint (protoAgent gates its mobile shell at `<768px`; protoPen's are
`1040`/`720`), so width breakpoints all miss it and fall back to the dense desktop rail. So we
switch the shell on **touch capability** — `@media (hover: none) and (pointer: coarse)` — not
width.

## Decisions

- **One responsive codebase**, capability-switched (not a separate Deck build).
- **Chat is the root/spine**, not 1-of-7 rails. protoPen already has the load-bearing
  invariant: `ChatSurface` mounts for the app's life and only toggles visibility, so the SSE
  stream never drops. We promote it from "the Home surface" to the base layer.
- **Bottom thumb-nav** replaces the far-left vertical rail: Chat · Engage · Findings ·
  Activity · Tools. System → a topbar gear. Terminal + the right panel (Notes/Beads) are
  desktop-only for now (open question).
- **Surfaces push over chat** and dismiss with Back (P1 gets the slide animation; P0 swaps
  the full-screen surface, chat staying mounted beneath).
- **Autonomy drives in a chat tab** (P2): a goal opens a dedicated tab, the OODA loop streams
  in live (dovetails with the `chat.resumed` `↻ agent-initiated` turns shipped in #311);
  close = detach (headless) or stop.
- **Keep the Pilot-Protocol skin** (green `#3ee07a` / mono / sharp corners / caps). This is a
  layout + ergonomics change, not a reskin.

Interactive mockup: https://claude.ai/code/artifact/1a153cec-ee29-4329-9976-c76696b3cb2e

## Phasing

- **P0 (this slice)** — capability-switched shell + chat-as-root + bottom thumb-nav. Hide the
  desktop rail + right panel + Home hero on handheld; chat fills the stage; thumb-nav drives
  the same `surface` state. Reuses every existing surface untouched.
- **P1** — touch floor (44px+ targets, larger arm's-length type, no hover-only affordances,
  pointer events for drag), on-screen-keyboard inset (`visualViewport → --kb-inset`),
  `viewport-fit=cover` + safe-area, the surface push-over slide animation.
- **P2** — goals/engagement drive-in-a-chat-tab (attach/detach). *Built.*
- **P3** — gamepad / Steam-Input focus model for Game Mode. *Built.*

## P0 implementation notes

- `apps/web/src/lib/useIsHandheld.ts` — capability query hook, with a `?shell=handheld|desktop`
  URL override so the handheld shell is previewable in a desktop browser.
- `apps/web/src/app/BottomNav.tsx` — the thumb-nav (drives `surface`/`setSurface`).
- `apps/web/src/app/App.tsx` — `data-shell` attribute on `.app-shell`; workspace column style
  applied desktop-only; System gear in the topbar; `<BottomNav>` between the workspace and the
  footer.
- `apps/web/src/app/theme.css` — `.app-shell[data-shell="handheld"]` rules (single-column
  workspace, hide rail/right-panel/footer/home-hero, bottom-nav row + styling).

Validate on the Deck at `100.98.241.57` (kiosk), and in a desktop browser via `?shell=handheld`.

## P2 implementation notes — drives in a chat tab

The join was already there: goals are keyed server-side by `session_id`, which **is**
the chat session id the console streams on. So a goal set with `/goal` in a tab already
*is* that tab's drive — P2 is about making that visible and giving it an exit.

- `apps/web/src/chat/drives.ts` — one app-wide poll of `/api/goals` (10s, paused while
  the page is hidden), sliced per session: `useDrives` / `useDrive` / `refreshDrives`.
  Refetches eagerly when a turn settles or a `chat.resumed` lands.
- `apps/web/src/chat/DriveStrip.tsx` — the drive header above the message list:
  condition · iteration · verifier, with **Detach** and **Stop**.
- Tab strip: a drive tab swaps its status dot for a radar badge, toned by goal status.
- Closing a drive tab is a three-way choice (`ConfirmDialog` grew an optional middle
  button): *Stop goal & close* · *Detach & close* · *Cancel*.
- **Attach** (`GoalsSurface`): binds a chat tab to a goal's session — adopting the
  server's id verbatim (`chatStore.attachSession`) and seeding it from the new
  `GET /api/chat/{session_id}/history` — so a headless drive's turns land in front of
  you. `POST /api/goal/{session_id}/detach` is the other direction.
- Thumb-nav Chat shows a pulsing warning-tone pip while any drive is active, including
  a detached one with nothing streaming locally.

**How detach actually keeps running.** A goal only advances while a turn runs on its
session, and those turns are pumped by whoever holds the stream — so closing the tab
would strand it. `operator_api/drives.py` hands the loop to the scheduler instead: a
one-shot job on the same `context_id`, which fires back through the A2A loopback with
`origin="scheduler"`, runs the goal loop to a verdict server-side, and pushes its answer
over `chat.resumed` for a console that re-attaches. Clearing a goal cancels that pending
job (a job outliving its goal would wake the agent to "continue" nothing).

## P3 implementation notes — gamepad / Steam Input

In Game Mode there is no cursor unless the operator drags a trackpad, so the shell has
to be drivable. Depending on the Steam Input layout bound to the kiosk the Deck's
controls arrive as **either** a real gamepad **or** emulated keyboard/mouse — both are
translated into one intent vocabulary, so neither path is the "real" one.

- `apps/web/src/lib/gamepad.ts` — rAF polling (only while a pad is attached) →
  intents. A confirm · B back · X composer · L1/R1 surface · L2/R2 scroll · Start
  system · d-pad/left-stick directions · right-stick scroll. Directions auto-repeat.
- `apps/web/src/lib/spatialNav.ts` — directional focus by geometry (nearest focusable
  in the pressed direction, cross-axis drift penalised). DOM order is the wrong answer
  for a d-pad.
- `apps/web/src/app/useGamepadShell.ts` — binds intents to the shell (Back dismisses a
  dialog first, then the pushed-over surface; bumpers cycle `NAV_SURFACES`), plus a
  keyboard mirror for key-emulating layouts. Both are inert unless gamepad mode is on
  and never fire while the operator is typing, so the desktop is untouched.
- `.app-shell[data-gamepad="on"]` turns on an always-visible accent focus ring — with a
  pad, the ring *is* the pointer. `?nav=gamepad` forces the mode on when Steam Input
  emulates keyboard/mouse and no pad ever connects.
