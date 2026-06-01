# The control stack — goals, workflows, playbooks, subagents, skills

protoPen has five concepts that all look like "automation" and blur together:
**goals, workflows, playbooks, subagents, and skills**. They aren't peers — they
are **altitudes of one control loop**, plus skills as an orthogonal **memory
layer** beside it. This page locks the model so it's clear *what each is, how they
compose, and when to reach for which*.

(Adapted from protoAgent's ADR 0009. The difference: protoPen has **two**
orchestration primitives — workflows *and* playbooks — where protoAgent has one.)

## The stack

```
GOAL       autonomy        decides WHEN to stop   (re-invoke the agent until a verifier passes)
  ▲ drives
WORKFLOW   orchestration   decides the ORDER      (a saved DAG of SUBAGENT steps — reasoning per step)
PLAYBOOK   orchestration   decides the ORDER      (a fixed sequence of TOOL actions — deterministic, no LLM)
  ▲ dispatch
SUBAGENT   execution       does the WORK          (the LLM-worker primitive; task = 1, batch = N parallel)
· · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · ·
SKILL      memory          teaches HOW            (retrieved methodology injected into ANY turn)
```

**Workflows and playbooks sit at the same altitude** — both are *saved, named,
parameterized recipes*. They differ only in **what they dispatch**: a workflow
runs **subagents** (LLM workers that reason per step); a playbook runs **tools**
(a deterministic chain, no model in the loop). That's the whole distinction.

## One-line definitions (so they stop blurring)

- **Skill** *(memory)* — reusable methodology the model **retrieves**; it never
  runs, only advises. `SKILL.md` files (human-authored, pinned) + agent-emitted
  skills, retrieved by relevance and injected as `<learned_skills>` into any turn
  ([skills + ADR 0005](../reference/tools.md)). Dispatched by nothing; influences
  every layer.
- **Subagent / batch** *(execution)* — a scoped LLM worker that does one focused
  unit of work under a tool allowlist + turn cap. `task` runs one; a **batch**
  fans out N independent ones in parallel. The atom everything above is built
  from.
- **Workflow** *(orchestration of subagents)* — a saved DAG of subagent steps
  with templated I/O threading (ADR 0002). Reasoning happens *inside* each step.
- **Playbook** *(orchestration of tools)* — a saved, ordered sequence of **tool**
  actions with variable substitution and step conditions; no LLM
  ([Playbooks](../reference/playbooks.md)). Deterministic.
- **Goal** *(autonomy)* — re-invokes whole agent turns until a testable finish
  condition passes (or the budget runs out). Owns *when-to-stop*, defines no
  steps. *Thin in protoPen today — a config/status flag, not a full loop.*

## How they compose

- **Goal → agent turns.** Re-runs the agent graph with continuation prompts; the
  agent inside may call `task` / `run_workflow` / `playbook`, but the goal loop
  dispatches none directly — it just re-invokes and checks the finish condition.
- **Workflow → subagents.** `run_workflow` resolves inputs and runs each step as a
  subagent; independent steps parallelize.
- **Playbook → tools.** `run_playbook` runs each step's tool action in order via
  the shared dispatcher (the same one the agent's `playbook` tool uses), with
  `${var}` / `${steps.x.output}` threading and findings-aware conditions.
- **Skill → context (all layers).** `KnowledgeMiddleware.before_model` injects
  top-k skills on lead + subagent turns; a retrieved skill also surfaces its
  declared `tools:` as a `<relevant_tools>` hint (ADR 0005). Subagents may *emit*
  new skills — the one feedback edge Execution → Memory.

## Decision rules

| Question | Use | Because |
|---|---|---|
| reasoning/judgment needed per step? | **Workflow** (subagent steps) | each step is an LLM worker |
| fixed tool sequence, no judgment? | **Playbook** (tool steps) | deterministic, no model cost |
| one-off mid-turn delegation? | **`task`** | ephemeral, single worker |
| many independent units at once? | **batch** | flat fan-out, no edges |
| know the *finish condition*, not the steps? | **Goal** | autonomy owns *until-when* |
| reusable methodology, not a runnable thing? | **Skill** | memory — advises, never dispatches |

## Naming note — Skills vs Playbooks vs Workflows

These are three *distinct* things that each get their own honest name:

- **Skills** = retrieved methodology *memory* (`SKILL.md` / `skills.db`).
- **Playbooks** = declarative *tool*-chains (`playbooks/library/*.yaml`).
- **Workflows** = declarative *subagent*-chains (ADR 0002).

> protoAgent (ADR 0009) renames *its* skills to "Playbooks" to dodge a collision
> with the A2A agent-card `skills` field. **protoPen does not** — "Playbooks" is
> already our tool-chains. We keep all three names as above.

## Where this shows up in the console

The [operator console](../guides/operator-console.md) mirrors the stack:

- **Agents** group → **Subagents** (execution: one or a batch) · **Workflows**
  (orchestrate subagents) · **Playbooks** (orchestrate tools).
- **Intel** group → **Skills** (memory — browse what the agent has learned), beside
  Targets / Search / Knowledge.
- **System** group → **Schedule** lives here: a *trigger* ("when"), orthogonal to
  the work-types above — not a fourth kind of work.
