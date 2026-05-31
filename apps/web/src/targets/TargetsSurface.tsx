import {
  ChevronDown,
  ChevronRight,
  KeyRound,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  Target,
} from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../lib/api";
import type {
  EngagementHistoryItem,
  IntelHit,
  TargetDetail,
  TargetSummary,
} from "../lib/types";

// Targets & Intel surface — browse discovered hosts (drill into ports / findings /
// credentials), review past engagements, and search across everything captured.
// Read-only over the target + knowledge stores; the agent's behaviour is untouched.

type View = "targets" | "search" | "engagements";

const DEVICE_TYPES = ["", "host", "router", "phone", "iot", "unknown"];

function sevClass(severity: string): string {
  const s = (severity || "").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(s)) return `sev-${s}`;
  return "sev-unknown";
}

export function TargetsSurface({ onError }: { onError: (message: string) => void }) {
  const [view, setView] = useState<View>("targets");

  // ── Targets browser ──────────────────────────────────────────────
  const [hostQuery, setHostQuery] = useState("");
  const [deviceType, setDeviceType] = useState("");
  const [targets, setTargets] = useState<TargetSummary[] | null>(null);
  const [targetsBusy, setTargetsBusy] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<TargetDetail | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);

  // ── Unified intel search ─────────────────────────────────────────
  const [intelQuery, setIntelQuery] = useState("");
  const [intelHits, setIntelHits] = useState<IntelHit[] | null>(null);
  const [intelBusy, setIntelBusy] = useState(false);

  // ── Engagement history ───────────────────────────────────────────
  const [engagements, setEngagements] = useState<EngagementHistoryItem[] | null>(null);
  const [engBusy, setEngBusy] = useState(false);

  async function loadTargets() {
    setTargetsBusy(true);
    try {
      const r = await api.targets({ q: hostQuery, deviceType, limit: 100 });
      setTargets(r.targets);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setTargetsBusy(false);
    }
  }

  async function toggleHost(id: number) {
    if (expandedId === id) {
      setExpandedId(null);
      setDetail(null);
      return;
    }
    setExpandedId(id);
    setDetail(null);
    setDetailBusy(true);
    try {
      setDetail(await api.target(id));
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
      setExpandedId(null);
    } finally {
      setDetailBusy(false);
    }
  }

  async function runIntelSearch() {
    if (!intelQuery.trim()) return;
    setIntelBusy(true);
    onError("");
    try {
      const r = await api.intelSearch(intelQuery, { k: 25 });
      setIntelHits(r.hits);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setIntelBusy(false);
    }
  }

  async function loadEngagements() {
    setEngBusy(true);
    try {
      const r = await api.engagementsHistory();
      setEngagements(r.engagements);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setEngBusy(false);
    }
  }

  // Lazy-load each view the first time it's opened.
  useEffect(() => {
    if (view === "targets" && targets === null) void loadTargets();
    if (view === "engagements" && engagements === null) void loadEngagements();
  }, [view]); // eslint-disable-line react-hooks/exhaustive-deps

  const refresh = () => {
    if (view === "targets") void loadTargets();
    else if (view === "engagements") void loadEngagements();
    else void runIntelSearch();
  };

  return (
    <section className="panel stage-panel targets-panel">
      <div className="panel-header">
        <div>
          <h1>Targets &amp; Intel</h1>
          <p className="panel-kicker">discovered hosts · captured findings · engagement history</p>
        </div>
        <button className="icon-button" type="button" onClick={refresh} title="Refresh">
          <RefreshCw size={16} />
        </button>
      </div>

      <div className="targets-tabs" role="tablist">
        <button role="tab" aria-selected={view === "targets"} className={view === "targets" ? "active" : ""} onClick={() => setView("targets")}>
          <Target size={14} /> Targets
        </button>
        <button role="tab" aria-selected={view === "search"} className={view === "search" ? "active" : ""} onClick={() => setView("search")}>
          <Search size={14} /> Intel search
        </button>
        <button role="tab" aria-selected={view === "engagements"} className={view === "engagements" ? "active" : ""} onClick={() => setView("engagements")}>
          <ShieldAlert size={14} /> Engagements
        </button>
      </div>

      <div className="stage-body">
        {/* ── Targets browser ──────────────────────────────────── */}
        {view === "targets" ? (
          <>
            <form
              className="knowledge-search"
              onSubmit={(event) => {
                event.preventDefault();
                void loadTargets();
              }}
            >
              <input
                value={hostQuery}
                onChange={(event) => setHostQuery(event.target.value)}
                placeholder="Filter hosts by IP, hostname, OS, vendor…"
                aria-label="Host filter"
                autoFocus
              />
              <select value={deviceType} onChange={(event) => setDeviceType(event.target.value)} aria-label="Device type">
                {DEVICE_TYPES.map((t) => (
                  <option key={t || "all"} value={t}>
                    {t || "all devices"}
                  </option>
                ))}
              </select>
              <button className="primary-button" type="submit" disabled={targetsBusy}>
                {targetsBusy ? <Loader2 className="spin" size={16} /> : <Search size={16} />}
                Filter
              </button>
            </form>

            <div className="target-list">
              {targets && targets.length ? (
                targets.map((t) => (
                  <article className="target-row" key={t.id}>
                    <button className="target-head" onClick={() => void toggleHost(t.id)} aria-expanded={expandedId === t.id}>
                      {expandedId === t.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      <span className="target-ip">{t.ip || t.mac || t.hostname || "—"}</span>
                      {t.hostname && t.hostname !== t.ip ? <span className="target-host">{t.hostname}</span> : null}
                      <span className="target-badge">{t.device_type}</span>
                      {t.os ? <span className="target-os">{t.os}</span> : null}
                      <span className="target-meta">{t.port_count} port{t.port_count === 1 ? "" : "s"}</span>
                      {t.finding_count ? <span className="target-meta target-meta-flag">{t.finding_count} finding{t.finding_count === 1 ? "" : "s"}</span> : null}
                    </button>

                    {expandedId === t.id ? (
                      <div className="target-detail">
                        {detailBusy || !detail ? (
                          <div className="empty-state stacked">
                            <Loader2 className="spin" size={16} />
                            <span>Loading profile…</span>
                          </div>
                        ) : (
                          <>
                            <div className="target-detail-grid">
                              {detail.mac ? <span><b>MAC</b> {detail.mac}</span> : null}
                              {detail.vendor ? <span><b>Vendor</b> {detail.vendor}</span> : null}
                              {detail.tags.length ? <span><b>Tags</b> {detail.tags.join(", ")}</span> : null}
                              <span><b>First seen</b> {detail.first_seen?.slice(0, 19).replace("T", " ") || "—"}</span>
                              <span><b>Last seen</b> {detail.last_seen?.slice(0, 19).replace("T", " ") || "—"}</span>
                            </div>

                            {detail.ports.length ? (
                              <div className="target-section">
                                <h3>Ports &amp; services</h3>
                                <div className="port-chips">
                                  {detail.ports.map((p) => (
                                    <span className={`port-chip ${p.state === "open" ? "open" : "closed"}`} key={`${p.port}/${p.protocol}`} title={p.banner}>
                                      {p.port}/{p.protocol}{p.service ? ` ${p.service}` : ""}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            ) : null}

                            {detail.findings.length ? (
                              <div className="target-section">
                                <h3>Findings ({detail.findings.length})</h3>
                                {detail.findings.map((f, i) => (
                                  <div className="finding-row" key={i}>
                                    <span className={`sev-pill ${sevClass(f.severity)}`}>{f.severity || "—"}</span>
                                    <span className="finding-title">{f.title || f.category || "(untitled)"}</span>
                                    {f.tool ? <span className="finding-tool">{f.tool}</span> : null}
                                    {f.value ? <p className="finding-value">{f.value}</p> : null}
                                  </div>
                                ))}
                              </div>
                            ) : null}

                            {detail.credentials.length ? (
                              <div className="target-section">
                                <h3><KeyRound size={13} /> Credentials ({detail.credentials.length})</h3>
                                {detail.credentials.map((c, i) => (
                                  <div className="cred-row" key={i}>
                                    <span className="cred-user">{c.username || "(unknown)"}</span>
                                    {c.hash_type ? <span className="cred-hash">{c.hash_type}</span> : null}
                                    <span className={`cred-state ${c.cracked ? "cracked" : ""}`}>{c.cracked ? "cracked" : c.has_secret ? "secret captured" : "—"}</span>
                                    {c.source ? <span className="cred-source">via {c.source}</span> : null}
                                  </div>
                                ))}
                                <p className="cred-note">Secret values are redacted in the console.</p>
                              </div>
                            ) : null}

                            {detail.notes ? <p className="target-notes">{detail.notes}</p> : null}
                          </>
                        )}
                      </div>
                    ) : null}
                  </article>
                ))
              ) : (
                <div className="empty-state stacked">
                  <Target size={18} />
                  <span>{targetsBusy ? "Loading hosts…" : "No discovered hosts yet."}</span>
                </div>
              )}
            </div>
          </>
        ) : null}

        {/* ── Unified intel search ─────────────────────────────── */}
        {view === "search" ? (
          <>
            <form
              className="knowledge-search"
              onSubmit={(event) => {
                event.preventDefault();
                void runIntelSearch();
              }}
            >
              <input
                value={intelQuery}
                onChange={(event) => setIntelQuery(event.target.value)}
                placeholder="Search hosts, findings, and threat intel…"
                aria-label="Intel query"
                autoFocus
              />
              <button className="primary-button" type="submit" disabled={intelBusy || !intelQuery.trim()}>
                {intelBusy ? <Loader2 className="spin" size={16} /> : <Search size={16} />}
                Search
              </button>
            </form>

            <div className="knowledge-results">
              {intelHits && intelHits.length ? (
                intelHits.map((hit, index) => (
                  <article className="intel-hit" key={`${hit.source}:${hit.id}:${index}`}>
                    <div className="intel-hit-head">
                      <span className={`intel-kind kind-${hit.kind}`}>{hit.kind}</span>
                      <span className="intel-hit-title">{hit.title || "—"}</span>
                      {hit.target ? <span className="intel-hit-target">{hit.target}</span> : null}
                      <span className="intel-hit-score">{hit.score.toFixed(2)}</span>
                    </div>
                    {hit.preview ? <p className="intel-hit-preview">{hit.preview}</p> : null}
                  </article>
                ))
              ) : (
                <div className="empty-state stacked">
                  <Search size={18} />
                  <span>{intelHits ? "No matches across captured intel." : "Search hosts, findings, and the knowledge store."}</span>
                </div>
              )}
            </div>
          </>
        ) : null}

        {/* ── Engagement history ───────────────────────────────── */}
        {view === "engagements" ? (
          <div className="eng-list">
            {engagements && engagements.length ? (
              engagements.map((e) => (
                <article className={`eng-card ${e.active ? "active" : ""}`} key={`${e.name}:${e.started_at}`}>
                  <div className="eng-head">
                    <span className="eng-name">{e.name}</span>
                    {e.mode ? <span className="eng-mode">{e.mode}</span> : null}
                    <span className={`eng-status ${e.active ? "live" : "done"}`}>{e.active ? "active" : e.ended_at ? "ended" : "open"}</span>
                  </div>
                  {e.scope ? <p className="eng-scope">{e.scope}</p> : null}
                  <div className="eng-meta">
                    <span>{e.started_at?.slice(0, 19).replace("T", " ") || "—"}</span>
                    {e.ended_at ? <span>→ {e.ended_at.slice(0, 19).replace("T", " ")}</span> : null}
                    <span className="eng-findings">{e.finding_count} finding{e.finding_count === 1 ? "" : "s"}</span>
                  </div>
                  {Object.keys(e.finding_counts).length ? (
                    <div className="eng-sev-row">
                      {Object.entries(e.finding_counts).map(([sev, n]) => (
                        <span className={`sev-pill ${sevClass(sev)}`} key={sev}>
                          {sev} {n}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </article>
              ))
            ) : (
              <div className="empty-state stacked">
                <ShieldAlert size={18} />
                <span>{engBusy ? "Loading engagements…" : "No engagements recorded yet."}</span>
              </div>
            )}
          </div>
        ) : null}
      </div>
    </section>
  );
}
