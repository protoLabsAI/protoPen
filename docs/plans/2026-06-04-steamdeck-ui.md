# Steam Deck Display-Friendly UI — Decision Doc (Parked)

> **Status: PARKED** (2026-06-04). Captured for later — other priorities come
> first. This is a design-intent record, **not** an implementation plan. When we
> pick it up, the "Open questions" below are the agenda; promote this to a
> task-by-task plan then.

## Context

protoPen is run **headless-primary** today — the operator drives it through the
agent / A2A interface, not the browser. The existing React operator console
(`apps/web/`, served at `:7870/app/`) is **desktop-oriented**: dense layout,
pointer-first interactions, sized for a laptop/monitor.

We want a separate **on-device UI that's comfortable on the Steam Deck's own
screen** — something you can actually use from the Deck in hand, not just from a
desktop browser pointed at it.

## Goal

A Deck-native operator surface: glanceable status, drive a chat/engagement turn,
watch tool activity, review findings/targets — all legible and operable on the
Deck's display with its input model.

## Constraints (the Deck hardware anchors the design)

- **Display:** 1280×800, ~7"/7.4" OLED, landscape. Design for *this* viewport —
  not a desktop breakpoint scaled down.
- **Input:** touch **and** controller (D-pad / sticks / face buttons / trackpads).
  Needs large touch targets and a sane controller focus/navigation model — not
  hover-dependent, not tiny click targets.
- **On-device:** runs against the local service on the Deck (`:7870`). Should feel
  like a handheld app, not a remote admin panel.
- **Backend contract is settled:** chat rides the same `/a2a`
  `SendStreamingMessage` (A2A 1.0) path the console now uses — see
  [A2A 1.0 migration](../../README.md) and PR #148. Whatever UI we build streams
  `task → statusUpdate (tool-call-v1 DataParts) → artifactUpdate → COMPLETED`.

## What exists to reuse / learn from

- `apps/web/src/lib/api.ts` — the A2A 1.0 streaming client (`streamChat`,
  tool-event parsing). Reusable as-is; this is data-layer, not presentation.
- `apps/web/src/chat/` — tool-call cards (protopen-75v) and chat surface. The
  *rendering* is desktop-tuned; the wire/state handling is sound.
- Existing surfaces (Targets & Intel, Workflows, Playbooks, Goals, Activity) map
  to candidate Deck views — but each needs a Deck-legible redesign.

## Open questions (the agenda when we unpark)

1. **Separate app or responsive mode?** New Deck-first surface vs. a responsive
   "deck" layout inside `apps/web`. (Leaning separate surface, shared data layer.)
2. **Controller navigation** — adopt a focus/roving-tabindex model, or lean
   touch-only first and add controller later?
3. **Launch path on the Deck** — browser at `:7870/app/`, a kiosk/Gamescope
   window, or a packaged app? Ties into how it's added to the Deck's UI.
4. **Scope of v1** — chat + tool cards + status only, or full surface parity?
5. **Theming** — reuse the green terminal theme, or a Deck-tuned variant?

## Non-goals (for now)

- Replacing the desktop console.
- Any in-browser screenshot verification gate on existing UI work — waived while
  usage is headless-primary.

## Next step when unparked

Walk the open questions with the operator → pick app shape + v1 scope → promote
this into a task-by-task implementation plan (`docs/plans/`) and file the work.

---

## Session log — 2026-06-05 (native build / install explored, re-parked)

Revisited the Deck direction and explored two adjacent ideas beyond the UI
redesign: a **native SteamOS build** and a **quick install path**. Captured the
findings below, then **decided to NOT pursue any of it yet** — focus instead on
the **information architecture of the *current* desktop console** while we do
more live testing on the actual app. Native build + packaging + installer stay
parked.

### What we found (so it's not re-discovered later)

- **A PWA scaffold already exists but is stale.** `static/manifest.json`
  (`display: standalone`, theme color, icons) and `static/sw.js` (served with
  `Service-Worker-Allowed: /`) are wired in `server/app.py`. But the manifest is
  leftover **protoAgent** boilerplate ("AI research agent… tracks the latest in
  AI/ML") — wrong identity, not Deck-tuned. "Installable app" is ~half-wired.
- **Tauri was deliberately NOT ported.** `server/app.py` comment: *"Webview-only:
  the Tauri desktop wrapper is intentionally not ported."* A true native-binary
  path is greenfield here, not a revival.
- **Read-only rootfs fragility.** Per the setup guide + SteamOS memory notes, OS
  updates wipe the `steamos-readonly disable` + `/etc/sudoers.d/zz-deck` +
  pacman/BlackArch layering. A venv-in-`$HOME` install is fragile across updates;
  a Flatpak (lives in `/home`) would be the update-resilient answer — but it's
  the heaviest lift, and BlackArch tools still live outside it.

### Packaging spectrum (for when we do unpark "native")

1. **Kiosk Non-Steam Game** — `chromium --kiosk --app=http://localhost:7870/app/`
   as a Non-Steam shortcut; launches from Game Mode, Steam Input drives the
   controller; backend as a `systemd --user` service. Cheapest "native feel",
   reuses the SPA as-is.
2. **PWA standalone** — fix the manifest, install from Chromium. Lightest, but
   Desktop-Mode-bound and weak controller story.
3. **Flatpak / Tauri package** — webview + backend sidecar, update-resilient,
   most native, heaviest lift (and Tauri is un-ported).

A **quick-install script** (`install.sh` automating the setup-doc + a service +
launcher shortcut) is valuable independent of which packaging tier we pick —
file it when we unpark.

### Decision (2026-06-05)

> **Don't jump the shark.** Native SteamOS build, packaging, and the installer
> are **parked**. This round: revisit and improve the **IA of the current
> desktop console** (`apps/web`) and do more live testing on the running app.
> The Deck-native surface + native-build work resumes only after the IA settles.

### Current IA snapshot (the thing we're now revisiting)

Left rail = 4 top-level surfaces, each with sub-tabs (`apps/web/src/app/App.tsx`):

| Surface | Icon | Sub-tabs |
|---|---|---|
| **Chat** | MessageSquare | `conversation`, `activity` (+ workspace note tabs) |
| **Intel** | Target | `targets`, `search`, `knowledge`, `engagements`, `skills` |
| **Agents** | Network | `goals`, `subagents`, `workflows`, `playbooks` |
| **System** | Gauge | `status`, `audit`, `schedule` |

≈14 sub-views across 4 rails — dense, desktop-tuned. This is the starting point
for the IA pass.
