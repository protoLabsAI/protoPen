import { ListChecks, Loader2, Play, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "../lib/api";
import type { PlaybookRunResult, PlaybookSummary } from "../lib/types";

// Operator surface for playbooks — the 23 declarative tool-chain recipes
// (playbooks/library/*.yaml). Browse the library, fill a recipe's variables, and
// fire it manually; the run reuses the same dispatch + runner the agent's
// `playbook` tool uses. Mirrors WorkflowsSurface's list→configure→run shape.

function stepTone(status: string): string {
  if (status === "completed") return "ok";
  if (status === "failed") return "error";
  if (status === "running") return "warning";
  return "muted"; // pending / skipped
}

export function PlaybooksSurface({ onError }: { onError: (message: string) => void }) {
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[] | null>(null);
  const [selected, setSelected] = useState<string>("");
  const [vars, setVars] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<PlaybookRunResult | null>(null);

  async function load() {
    try {
      const r = await api.playbooks();
      setPlaybooks(r.playbooks);
      if (r.playbooks.length && !r.playbooks.some((p) => p.name === selected)) {
        setSelected(r.playbooks[0].name);
      }
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }
  useEffect(() => {
    void load();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const current = useMemo(() => playbooks?.find((p) => p.name === selected) ?? null, [playbooks, selected]);

  // Seed the variable form (recipe defaults) when the selected playbook changes.
  useEffect(() => {
    if (!current) return;
    setVars({ ...current.variables });
    setResult(null);
  }, [selected]); // eslint-disable-line react-hooks/exhaustive-deps

  const mode = current?.mode ?? "passive";

  async function run() {
    if (!current) return;
    setRunning(true);
    setResult(null);
    onError("");
    try {
      setResult(await api.runPlaybook(current.name, vars));
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="panel stage-panel">
      <div className="panel-header">
        <div>
          <h1>Playbooks</h1>
          <p className="panel-kicker">
            {playbooks ? `${playbooks.length} tool-chain recipe${playbooks.length === 1 ? "" : "s"}` : "loading…"}
          </p>
        </div>
        <button className="icon-button" type="button" onClick={() => void load()} title="Refresh">
          <RefreshCw size={16} />
        </button>
      </div>

      <div className="stage-body">
        {playbooks && !playbooks.length ? (
          <div className="subagent-row">
            <div>
              <strong>No playbooks found</strong>
              <span>Drop a recipe in playbooks/library/.</span>
            </div>
          </div>
        ) : null}

        {playbooks && playbooks.length ? (
          <label className="field">
            <span>Playbook</span>
            <select value={selected} onChange={(event) => setSelected(event.target.value)}>
              {playbooks.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        {current ? (
          <>
            <div className="playbook-meta">
              <span className={`mode-pill mode-${mode}`}>{mode}</span>
              {current.tags.map((t) => (
                <span className="tag-chip" key={t}>
                  {t}
                </span>
              ))}
            </div>
            {current.description ? <p className="workflow-desc">{current.description}</p> : null}

            <div className="workflow-steps">
              {current.steps.map((step, i) => (
                <div className="workflow-step" key={`${step.name}-${i}`}>
                  <ListChecks size={14} />
                  <strong>{step.name}</strong>
                  <span className="workflow-step-sub">
                    {step.tool}.{step.action}
                  </span>
                </div>
              ))}
            </div>

            {Object.keys(current.variables).length ? (
              <div className="subagent-grid">
                {Object.keys(current.variables).map((key) => (
                  <label className="field" key={key}>
                    <span>{key}</span>
                    <input
                      value={vars[key] ?? ""}
                      onChange={(event) => setVars((prev) => ({ ...prev, [key]: event.target.value }))}
                      placeholder={current.variables[key] || "optional"}
                    />
                  </label>
                ))}
              </div>
            ) : null}

            <div className="panel-actions">
              {current.requires_engagement ? (
                <span className="playbook-warn">
                  ⚠ {mode} — needs an active engagement; targets must fall within its scope
                </span>
              ) : null}
              <button className="primary-button" type="button" onClick={() => void run()} disabled={running}>
                {running ? <Loader2 className="spin" size={16} /> : <Play size={16} />}
                Run
              </button>
            </div>
          </>
        ) : null}

        {result ? (
          <div className="workflow-result">
            <h2>
              {result.name} — {result.progress}
              {result.failed ? " · failed" : result.completed ? " · done" : ""}
            </h2>
            <div className="playbook-run-steps">
              {result.steps.map((s, i) => (
                <details className="playbook-run-step" key={`${s.name}-${i}`}>
                  <summary>
                    <span className={`step-dot tone-${stepTone(s.status)}`} />
                    <strong>{s.name}</strong>
                    <span className="workflow-step-sub">
                      {s.tool}.{s.action}
                    </span>
                    <span className="playbook-run-status">{s.status}</span>
                  </summary>
                  {s.error ? <pre className="output-block error">{s.error}</pre> : null}
                  {s.output ? <pre className="output-block">{s.output}</pre> : null}
                </details>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
}
