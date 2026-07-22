# Chat-first Deck UI

**Status:** in progress (P0) · **Owner:** kj · **Date:** 2026-07-22

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
- **P2** — goals/engagement drive-in-a-chat-tab (attach/detach).
- **P3** — gamepad / Steam-Input focus model for Game Mode.

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
