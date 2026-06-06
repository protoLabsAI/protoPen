# Companion IA Restructure — Implementation Slices

> **Status: ACTIVE (2026-06-06).** Scopes tracker issue **protopen-cym** (P2) into
> shippable slices. Restructures the `apps/web` console from operator-console rails
> (Chat / Intel / Agents / System) to the autonomous-first **companion nouns**
> (Home/Companion · Engagement · Findings · Activity · Capabilities · System) from
> `2026-06-05-companion-ui-vision.md`. The Capabilities catalog (B-subtext) is its
> own issue, **protopen-1vd**, picked up in Slice 4.

## Current IA (verified 2026-06-06, `apps/web/src/app/App.tsx:953`)

Rail state is local `useState` (`surface` + per-surface `*Tab`) — **no router**, so
the restructure is rail buttons + surface conditionals + state enums, not routing.

| Rail (`surface`) | Sub-tabs |
|---|---|
| **Chat** | Conversation · Activity |
| **Intel** | Targets · Search · Knowledge · Engagements · Skills |
| **Agents** | Goals · Subagents · Workflows · Playbooks |
| **System** | (status) |

Topbar already carries `CompanionStatus` (#184) — the presence seed.

## Target IA → where each piece comes from

| Target rail | Role | Re-homed from |
|---|---|---|
| **Home / Companion** | Glanceable spine: presence, what it's doing *now*, pending-approval, findings ticker, chat as the steering channel | `CompanionStatus` (topbar) + `ChatSurface` (Chat·Conversation) |
| **Engagement** | Scope a target, pick goal/playbook, set passive/active, go + watch it self-drive | Intel·Engagements + Agents·Goals + Agents·Playbooks + `POST /api/engagement` |
| **Findings** | What it learned | Intel·Targets · Intel·Search · Intel·Knowledge |
| **Activity** | Auditable timeline | Chat·Activity (promoted to top-level rail) |
| **Capabilities** *(B-subtext, protopen-1vd)* | Browseable catalog — fire manually or hand to agent | Intel·Skills + Agents·Subagents + Agents·Workflows |
| **System** | Health/plumbing | System (unchanged) |

Net: the **control stack stops being the `Agents` rail** and splits — autonomy
primitives (goals/playbooks) move *behind Engagement*, manual primitives
(subagents/workflows/skills) become the *Capabilities catalog*. `Intel` collapses
into `Findings`. `Activity` graduates from a Chat sub-tab to a rail.

## Slices

Each slice keeps the app shippable. Build order is risk-ascending: mechanical
regroup first, new surfaces after.

### Slice 1 — Rail skeleton + regroup  ← START HERE
Pure re-labelling and re-grouping of **existing** surfaces; no new feature code.
- Replace the four rail buttons (`App.tsx:953`) with the six companion rails.
- Migrate the `surface` enum: `chat|intel|agents|system` →
  `home|engagement|findings|activity|capabilities|system`.
- Re-home sub-tabs per the table: `Findings` = the three Intel tabs;
  `Activity` becomes its own rail (lift `ActivitySurface` out of the Chat group,
  drop the Chat·Activity sub-tab + its unread-badge plumbing which now belongs to
  the Activity rail button); `Engagement`/`Capabilities` are placeholder shells in
  this slice that simply *re-mount the existing tab surfaces* under new names.
- `Home` provisionally mounts `ChatSurface` (the steering channel) so nothing is
  orphaned before Slice 2.
- Keep every existing surface component as-is — this slice only moves where they
  mount and what the rail says.
- **Acceptance:** every surface reachable under the new rails; `scripts/smoke.sh`
  + web build green; no dead tab.

### Slice 2 — Home / Companion surface
The spine. Promote `CompanionStatus` from a topbar strip to a full landing surface.
- Compose: presence/state (engagement active? mode?) · "doing now" (live agent
  status from the event stream) · pending-approval indicator (the `hitl-v1`
  approval card from #181/#182, surfaced here) · recent-findings ticker
  (`/api/activity` or targets delta) · chat steering entry.
- Consumes only existing endpoints (`/api/engagement`, `/api/activity`, runtime
  status, the shipped HITL console) — presentation, not new backend.
- Chat moves into Home as the conversational steering channel.
- **Acceptance:** Home answers "is it running, what's it doing, does it need me?"
  at a glance; a parked HITL turn shows its approve/deny card on Home.

### Slice 3 — Engagement-as-object surface
Promote the engagement from an API call to the central UI object.
- One surface to scope a target, pick goal/playbook, set passive/active, hit go,
  and watch live progress — wiring `POST /api/engagement` {start|end|set_mode} +
  `GoalsSurface` + `PlaybooksSurface` + the Engagements log into a single
  "set it loose" panel with lifecycle + live progress.
- **Acceptance:** start→drive→end an engagement end-to-end from this one surface;
  mode ceiling settable up front (per the Slice-2 drop in the autonomy plan —
  agent self-escalates within the ceiling).

### Slice 4 — Capabilities catalog  (= protopen-1vd, P3)
The B-subtext. Reframe Skills + Subagents + Workflows from lists into a friendly,
browseable catalog of what protoPen can DO (WiFi recon, OSINT, scanning,
RF/hardware) — pick one, fire it manually, or hand it to the agent. Backed by the
tools/skills registry. De-emphasised vs the autonomous loop. Scoped in its own
issue; lands last so the autonomous spine reads as primary.

## Out of scope
- Deck-native shell (parked — `2026-06-04-steamdeck-ui.md`).
- New backend autonomy — the engine already exists (goals loop, EngagementManager,
  HITL producer #182). This is UX framing.
