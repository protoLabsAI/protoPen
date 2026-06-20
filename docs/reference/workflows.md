# Workflows

A **workflow** is a declarative, multi-step recipe over sub-agents (ADR 0002) — a
small DAG where each step delegates to a named [subagent](/explanation/architecture)
and later steps consume earlier ones' output. Where a [playbook](/reference/playbooks)
chains *tools* deterministically, a workflow chains *sub-agents* (each an LLM
worker), so it's the right tool when each step needs reasoning, not just a command.

Workflows are YAML files under the workflows dir (`workflows/`, configurable via
`workflows.dir`). They're enabled by `workflows.enabled` (default true) and run via
the `run_workflow` tool, `POST /api/workflows/{name}/run`, or saved by the agent
with `save_workflow`. See also [The Control Stack](/explanation/control-stack).

## Recipe schema

```yaml
name: threat-brief            # required — unique slug
description: Scan a topic, deep-analyze the hits, write an intel digest.
version: 1

inputs:                       # named parameters, referenced as {{inputs.<name>}}
  - name: topic
    required: true

steps:                        # required, non-empty — the DAG
  - id: scan                  # required, unique within the recipe
    subagent: threat_scanner  # required — must be a known subagent
    prompt: |
      Scan CVE feeds and GitHub for recent threats related to: {{inputs.topic}}.
      Return a structured list (CVE IDs, sources, severity, 1-line summary).

  - id: analyze
    subagent: vuln_analyst
    depends_on: [scan]        # this step waits for `scan` and can read its output
    prompt: |
      Rate exploitability for the significant items below. Cite evidence.
      {{steps.scan.output}}

  - id: brief
    subagent: intel_reporter
    depends_on: [scan, analyze]
    prompt: |
      Write a concise, actionable digest on {{inputs.topic}}.
      Scan: {{steps.scan.output}}
      Analysis: {{steps.analyze.output}}

output: "{{steps.brief.output}}"   # optional — the recipe's final result
```

### Fields

| Field | Required | Notes |
|---|---|---|
| `name` | ✅ | Unique slug. |
| `description` | — | One-line summary (shown in `/api/workflows`). |
| `version` | — | Recipe schema version. |
| `inputs[]` | — | Each `{ name, required }`. Referenced in templates as `inputs.<name>`. |
| `steps[]` | ✅ | Non-empty. Each step: `id`, `subagent`, `prompt`, optional `depends_on`. |
| `steps[].id` | ✅ | Unique within the recipe. |
| `steps[].subagent` | ✅ | Must be a registered [subagent](/explanation/architecture). |
| `steps[].prompt` | ✅ | Templated; receives inputs + upstream step outputs. |
| `steps[].depends_on` | — | List of step ids this step waits for (defines the DAG edges). |
| `output` | — | Template for the recipe's final return value. |

### Templating

Two reference forms are interpolated into `prompt` and `output`:

```
{{inputs.<name>}}        # a declared input
{{steps.<id>.output}}    # the output of a prior step
```

Every reference is validated up front: it must resolve to a declared input or an
existing step id, `depends_on` must name real steps, and the steps must form a DAG
(**cycles are rejected**). An invalid recipe fails validation before any sub-agent
runs.

## Running a workflow

- **In chat / by the agent:** `run_workflow(name, inputs)` — only the lead agent
  gets this tool, so workflows can't recurse.
- **Operator API:** `POST /api/workflows/{name}/run` with an `inputs` object;
  `GET /api/workflows` lists the available recipes.
- **Authoring on the fly:** the agent can persist a new recipe with `save_workflow`.

## Workflow vs. playbook vs. goal

| Use… | When |
|---|---|
| [**Workflow**](/reference/workflows) | A fixed multi-step pipeline where each step needs an LLM sub-agent (scan → analyze → report). |
| [**Playbook**](/reference/playbooks) | A deterministic tool sequence (no reasoning per step) with risk gating. |
| [**Goal**](/reference/goals) | An open-ended objective with a verifier — the agent decides the steps and loops until done. See [Autonomy](/explanation/autonomy). |
