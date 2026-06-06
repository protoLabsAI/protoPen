# protoPen Companion UI — Product Vision / IA North Star

> **Status: ACTIVE north-star (2026-06-05).** Not a task plan yet — this is the
> product posture the IA work builds toward. Promote slices into dated
> implementation plans as we go. Supersedes the "tidy the 4 admin rails" framing.

## The shift

protoPen has been driven **headless-primary** with a **desktop operator console**
(`apps/web`): rails for Chat / Intel / Agents / System. That console's mental
model is *"I supervise an agent and inspect its work."*

The product we're actually building is a **self-driving pentest companion** — a
handheld field device in the spirit of **Pwnagotchi** (Pi-based, self-learning
WiFi capture, character/face presence) and **Bjorn** (Pi-based, autonomously
scans/attacks the network, displays results as a character), with **Flipper
Zero's** approachable capability-menu UX as the secondary layer. AI-driven like
it is now, but the human-facing surface is a **running engagement + a companion
presence**, not a dense tool list.

## Posture decision (2026-06-05)

> **Autonomous-first (A), with capability-first (B) as subtext.**
>
> - **(A) spine** — you scope it, it *runs the engagement itself* (picks tools,
>   chains recon→enum→capture), you mostly **glance and steer/approve**. The IA
>   centers on companion status + a steer/approve loop.
> - **(B) subtext** — a Flipper-style **Capabilities catalog** lives underneath:
>   browse what it can do, fire one manually, or hand it to the agent. Opt-in,
>   de-emphasized vs the autonomous loop — present, not the spine.

## IA implied by A-first

| Rail | Role | Built from (already exists) |
|---|---|---|
| **Home / Companion** | The spine. Glanceable presence: engagement active? mode (passive/active)? what is it doing *right now*? recent-findings ticker. Chat = the conversational steering channel. Pending-approval prompts surface here. | EngagementManager, Activity feed, chat, goals loop |
| **Engagement** | Scope a target, pick goal/playbook, set passive/active, hit go and watch it self-drive. Where you set it loose. | `POST /api/engagement`, goals/autonomy loop, playbooks |
| **Findings** | What it learned — targets, captured intel, knowledge. | Targets & Intel surface |
| **Activity** | Auditable timeline of what it did. | Activity thread |
| **Capabilities** *(B subtext)* | Friendly catalog of tools/skills — browse, trigger manually, or hand to agent. Secondary. | tools/skills registry |
| **System** | Health/plumbing — status, audit. | RuntimePanel etc. |

The **control stack stops being a rail you visit** and becomes the *autonomy
engine* behind **Engagement** (goals/workflows/playbooks). **Skills/tools stop
being a list** and become the **Capabilities** catalog. This also re-homes the
misfiled `skills` and collapses the overloaded `Intel` rail.

## The new interactions A-first requires (the real work)

These don't exist yet — they're the gap between today's console and the vision:

1. **Steer/approve loop.** The agent self-drives until it hits a gated step
   (e.g. passive→active escalation, a destructive tool). It surfaces an
   **approval card**; the human taps approve/deny/adjust. This is the heart of
   autonomous-first. Connects to the existing passive-gate / `requires_engagement`
   flag and engagement modes.

   **STATUS — half-built (found 2026-06-05).** The **backend HITL is already in
   protoPen and tested**: `a2a_executor.py` parks the task in
   `TASK_STATE_INPUT_REQUIRED` carrying a `hitl-v1` DataPart
   (`HITL_MIME = application/vnd.protolabs.hitl-v1+json`) — a JSON-schema **form**
   (`request_user_input`) *or* an Approve/Deny **approval** (`run_command`); the
   pause survives restart (`a2a_stores.py`) and is covered by
   `tests/test_a2a_handler.py`. The **frontend was never ported.** Upstream
   protoAgent has `apps/web/src/chat/HitlForm.tsx` (form + Approve/Deny card) +
   ChatSurface wiring; protoPen's web has none of it, and the `lib/api.ts`
   streamChat client doesn't list `INPUT_REQUIRED` as a handled state nor expose
   an `onInputRequired` handler/resume path — so a paused turn currently dangles
   in the console. **This is the first build slice**, and it's a contained port
   of our own backend's missing half (not an upstream-feature chase):
   - `lib/api.ts` — detect `TASK_STATE_INPUT_REQUIRED`, parse the `hitl-v1`
     DataPart, add `onInputRequired(payload)` + `HitlPayload`/`HitlFormStep`
     types; treat the pause as resumable, not terminal.
   - `HitlForm.tsx` — port the JSON-schema form **and** the Approve/Deny card.
   - `ChatSurface.tsx` — hold `hitl` state, render it, `resumeHitl(response)`
     sends the follow-up to the parked task.

   The approval card is reused as the **passive→active / destructive-tool gate**
   for autonomous-first — same `hitl-v1` approval payload.
2. **Companion presence / "face."** A glanceable status element conveying agent
   state — idle / recon-ing / waiting-for-approval / found-something. The
   Pwnagotchi/Bjorn character beat. New element.
3. **Engagement-as-object.** Promote the engagement from an API call to the
   central UI object with lifecycle, live progress, and a self-drive control
   panel.

## What already supports this (so A-first is buildable, not greenfield)

- **Autonomy engine exists** — verifier-backed goal loop + `set_goal` / `/goal`
  (read-only, no-shell verifiers). Self-driving primitive is there.
- **Engagement control exists** — `POST /api/engagement` {start|end|set_mode}
  drives the live `EngagementManager` singleton; passive/active modes gate tools.
- **Playbooks** (personal_osint etc.) + **workflows** = the chained-procedure
  layer the agent runs.
- **Activity thread** = the live "what it did" feed.

The gap is mostly **UX framing + the approval-gate interaction**, not new backend
autonomy.

## Relationship to the parked Deck/native work

The companion framing is what *justifies* the eventual Deck-native build — a
handheld companion wants to live in Game Mode, not a desktop browser. But that
stays **parked** (see `2026-06-04-steamdeck-ui.md`). We build the companion IA
in the **current web app** first, test it live, then the native shell comes later.

## Next step

Walk the IA against how engagements are actually driven → prototype the
**Home/Companion spine + steer/approve loop** in `apps/web` → test on the running
app → iterate. File the first slice as a dated plan when the shape settles.
