import { ChevronDown, ChevronRight, Loader2, Play, Square } from "lucide-react";
import { useState } from "react";

import { api } from "../lib/api";
import type { EngagementStatus } from "../lib/types";

// Engagement-as-object (IA restructure Slice 3, protopen-cym). Promotes the
// engagement from a bare API call to the central, controllable UI object: scope
// a target, set the passive/active/redteam ceiling, set it loose, watch live
// progress, end it — all from one surface. Wires the operator control endpoint
// (POST /api/engagement, #166) that drives the same EngagementManager the
// enforcement middleware checks, so starting here unblocks engagement-gated
// tools without waiting on the agent. Goals/Playbooks (the autonomy engine) and
// History live in sibling tabs on this rail.

const MODES = ["passive", "active", "redteam"] as const;
type Mode = (typeof MODES)[number];

const MODE_HINT: Record<Mode, string> = {
  passive: "Recon only — no active probing. The safe default.",
  active: "Active scanning/enumeration allowed.",
  redteam: "Full offensive scope — exploitation allowed.",
};

export function EngagementSurface({
  engagement,
  onChange,
  onError,
}: {
  engagement: EngagementStatus | null;
  onChange: (status: EngagementStatus) => void;
  onError: (message: string) => void;
}) {
  const active = engagement?.active ? engagement : null;
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [mode, setMode] = useState<Mode>("passive");
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);

  async function control(body: Parameters<typeof api.engagementControl>[0]) {
    setBusy(true);
    onError("");
    try {
      const status = await api.engagementControl(body);
      onChange(status);
    } catch (exc) {
      onError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  const currentMode = (active?.mode || "").toLowerCase();

  return (
    <section className="panel stage-panel">
      <div className="panel-header">
        <div>
          <h1>{active ? active.name || "Engagement" : "Engagement"}</h1>
          <p className="panel-kicker">
            {active
              ? `${active.phase || "—"} • ${active.mode || "—"} • ${active.total_findings} finding${active.total_findings === 1 ? "" : "s"}`
              : "Scope a target and set it loose. The agent self-drives within the mode ceiling."}
          </p>
        </div>
        {active ? (
          <button
            className="secondary-button"
            type="button"
            onClick={() => void control({ action: "end" })}
            disabled={busy}
            title="End the active engagement"
          >
            {busy ? <Loader2 className="spin" size={15} /> : <Square size={15} />}
            End engagement
          </button>
        ) : null}
      </div>

      <div className="stage-body engagement-control">
        {!active ? (
          // ── Scope form: start a new engagement ──────────────────────────
          <form
            className="engagement-start"
            onSubmit={(event) => {
              event.preventDefault();
              if (name.trim()) void control({ action: "start", name: name.trim(), scope: scope.trim(), mode });
            }}
          >
            <label className="field">
              <span>Name</span>
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="e.g. acme-q3-external"
                autoFocus
              />
            </label>
            <label className="field">
              <span>Scope</span>
              <input
                value={scope}
                onChange={(event) => setScope(event.target.value)}
                placeholder="target / CIDR / host (optional)"
              />
            </label>
            <div className="field">
              <span>Mode ceiling</span>
              <div className="segmented engagement-mode-pick">
                {MODES.map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={mode === m ? "active" : ""}
                    onClick={() => setMode(m)}
                  >
                    {m}
                  </button>
                ))}
              </div>
              <p className="field-hint">{MODE_HINT[mode]}</p>
            </div>
            <button className="primary-button" type="submit" disabled={busy || !name.trim()}>
              {busy ? <Loader2 className="spin" size={16} /> : <Play size={16} />}
              Start engagement
            </button>
          </form>
        ) : (
          // ── Live engagement: mode control + progress ────────────────────
          <div className="engagement-live">
            {active.scope ? <p className="panel-kicker">Scope: {active.scope}</p> : null}

            <div className="field">
              <span>Mode ceiling</span>
              <div className="segmented engagement-mode-pick">
                {MODES.map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={currentMode === m ? "active" : ""}
                    disabled={busy || currentMode === m}
                    onClick={() => void control({ action: "set_mode", mode: m })}
                  >
                    {m}
                  </button>
                ))}
              </div>
              <p className="field-hint">
                The agent self-escalates within this ceiling; raise or lower it live.
              </p>
            </div>

            <div className="severity-row">
              {Object.entries(active.finding_counts).map(([sev, count]) => (
                <span key={sev} className={`status-pill sev-${sev}`}>
                  {sev}: {count}
                </span>
              ))}
            </div>

            <div className="finding-list">
              {active.findings.length === 0 ? (
                <p className="panel-kicker">No findings logged yet.</p>
              ) : (
                active.findings.map((finding, index) => {
                  const open = expanded === index;
                  const hasDetail = Boolean(finding.detail);
                  return (
                    <div className="finding-row" key={`${finding.severity}-${finding.title}-${index}`}>
                      <button
                        type="button"
                        className="finding-head"
                        onClick={() => setExpanded(open ? null : index)}
                        aria-expanded={open}
                      >
                        {hasDetail ? (
                          open ? <ChevronDown size={14} /> : <ChevronRight size={14} />
                        ) : (
                          <span className="finding-bullet" />
                        )}
                        <span className={`status-pill sev-${finding.severity || "info"}`}>
                          {finding.severity || "—"}
                        </span>
                        <span className="finding-title">{finding.title || "(untitled)"}</span>
                      </button>
                      <div className="finding-sub">{finding.category || "—"}</div>
                      {open && hasDetail ? <pre className="finding-detail">{finding.detail}</pre> : null}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
