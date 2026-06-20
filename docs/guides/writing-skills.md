# Writing a Skill

A **skill** is a reusable methodology — a disciplined procedure the agent should
follow for a recurring kind of request (e.g. "subnet recon", "triage a web app").
Skills are portable `SKILL.md` files in the open AgentSkills format (the same shape
Claude Code and others use). The agent retrieves the right skill for a turn and
follows it. See [The Control Stack](/explanation/control-stack) for where skills
sit relative to goals, workflows, and playbooks.

## Anatomy of a SKILL.md

A skill is a folder containing a `SKILL.md`: YAML frontmatter + a markdown body.

```markdown
---
name: subnet-recon
description: Use this when asked to enumerate a subnet — map hosts, services, and quick wins.
tools: [dns_enum, network_enum, target_intel]   # optional — tools the skill relies on
user_only: false                                 # optional — see below
---

# Subnet Recon

1. Confirm the engagement scope and mode before touching anything.
2. Discover live hosts (start passive, escalate only if the mode allows).
3. Enumerate services on responsive hosts; record findings as you go.
4. Correlate against known target intel; flag anything notable.
5. Summarize: hosts, open services, and the top follow-ups.
```

### Frontmatter fields

| Field | Required | Notes |
|---|---|---|
| `name` | ✅ | Short unique slug. |
| `description` | ✅ | **The trigger signal** — phrase it as "Use this when the user asks you to …" so it's matched to the right requests. Capped at 1024 chars. |
| `tools` | — | Tool names the skill leans on (a relevance hint surfaced to the model, not a gate). |
| `user_only` | — | If `true`, the skill is **excluded from auto-retrieval** and reachable only on demand via `/skill <name>`. Use for situational or destructive procedures you don't want surfaced automatically. |

The markdown body is the step-by-step methodology. Name the tools and the order to
use them; keep it to a disciplined process, not a transcript.

## Where skills live

- **Bundled** skills ship in the repo under `skills/` (e.g. `skills/pentest/`,
  `skills/blue-team/`, `skills/security-research/`).
- **Live** skills go in the writable skills dir (`skills.dir`, default
  `/sandbox/skills`). Both roots are seeded into the FTS index on boot; on a name
  clash, the live one wins.
- **Agent-emitted** skills: the agent can persist a skill it just worked out with
  the `save_skill` tool — it then surfaces on matching future requests.

## How skills reach the agent — progressive disclosure

By default (`skills.progressive_disclosure: true`) the agent is shown a lightweight
`<available_skills>` **catalog** each turn — just names + descriptions — and pulls a
skill's full body **on demand** with the `load_skill(name)` tool when it decides to
use one. This scales as the library grows and keeps per-turn context small. Set
`skills.progressive_disclosure: false` for the legacy behavior (inject the bodies of
the top-k matched skills every turn).

`user_only` skills never appear in the catalog; run them explicitly:

```
/skill <name>          # run a skill on demand (the only way to reach a user_only skill)
```

## Tips

- Lead the `description` with the trigger ("Use this when…") — retrieval matches on
  it, so a vague description means the skill won't fire when it should.
- Keep skills tool-aware but tool-agnostic about specifics — describe the approach,
  let the agent pick exact arguments.
- Re-saving a skill with the same `name` refines it rather than duplicating.
