import { Loader2, RefreshCw, Sparkles, X } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../lib/api";
import type { GoalState } from "../lib/types";

// Goals — the autonomy layer (top of the control stack). Read-only browse + clear;
// goals are SET from chat with `/goal <condition>` and loop the agent toward a
// verifier (findings / llm) until met, exhausted, or unachievable.

function statusTone(status: string): string {
  if (status === "achieved") return "ok";
  if (status === "active") return "warning";
  return "error"; // exhausted | unachievable
}

export function GoalsSurface({ onError }: { onError: (message: string) => void }) {
  const [enabled, setEnabled] = useState(true);
  const [goals, setGoals] = useState<GoalState[] | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    try {
      const r = await api.goals();
      setEnabled(r.enabled);
      setGoals(r.goals);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    void load();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function clear(sessionId: string) {
    try {
      await api.clearGoal(sessionId);
      void load();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <section className="panel stage-panel">
      <div className="panel-header">
        <div>
          <h1>Goals</h1>
          <p className="panel-kicker">autonomy — loop the agent toward a verifier</p>
        </div>
        <button className="icon-button" type="button" onClick={() => void load()} title="Refresh">
          {busy ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
        </button>
      </div>

      <div className="stage-body">
        {!enabled ? (
          <div className="empty-state stacked">
            <Sparkles size={18} />
            <span>Goal mode is disabled (set goals.enabled in config).</span>
          </div>
        ) : goals && goals.length ? (
          <div className="goal-list">
            {goals.map((g) => {
              const vtype = String((g.verifier && g.verifier.type) || "llm");
              return (
                <article className="goal-card" key={`${g.session_id}:${g.condition}`}>
                  <div className="goal-head">
                    <span className={`goal-status tone-${statusTone(g.status)}`}>{g.status}</span>
                    <span className="goal-condition">{g.condition}</span>
                    {g.status === "active" ? (
                      <button className="icon-button" type="button" title="Clear goal" onClick={() => void clear(g.session_id)}>
                        <X size={14} />
                      </button>
                    ) : null}
                  </div>
                  <div className="goal-meta">
                    <span>via {vtype}</span>
                    {g.mode === "monitor" ? (
                      <span>monitor</span>
                    ) : (
                      <span>
                        iteration {g.iteration}/{g.max_iterations}
                      </span>
                    )}
                    <span className="goal-session">{g.session_id}</span>
                  </div>
                  {g.last_reason ? <p className="goal-reason">{g.last_reason}</p> : null}
                </article>
              );
            })}
          </div>
        ) : (
          <div className="empty-state stacked">
            <Sparkles size={18} />
            <span>
              {busy ? "Loading goals…" : 'No goals. Set one in chat: /goal <condition> (e.g. "find a critical vuln").'}
            </span>
          </div>
        )}
      </div>
    </section>
  );
}
