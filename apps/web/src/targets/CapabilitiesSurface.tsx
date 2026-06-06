import { Loader2, RefreshCw, Search, Send } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "../lib/api";
import type { CapabilityTool } from "../lib/types";

// Capabilities catalog (protopen-1vd) — the B-subtext of the autonomous-first
// IA. A friendly, browseable, searchable menu of what protoPen can DO, grouped
// into approachable categories, instead of a dense 80-tool list. Pick one and
// hand it to the agent (prefills the chat steering channel). Backed by the live
// tool registry via GET /api/tools. De-emphasised vs the autonomous loop — this
// is the manual layer, present but not the spine.

export function CapabilitiesSurface({
  onAskAgent,
  onError,
}: {
  onAskAgent: (prompt: string) => void;
  onError: (message: string) => void;
}) {
  const [tools, setTools] = useState<CapabilityTool[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");

  async function load() {
    setLoading(true);
    try {
      const r = await api.tools();
      setTools(r.tools);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);

  // Filter by name + summary, then group by category (preserving the backend's
  // category sort — Object insertion order follows first-seen, already sorted).
  const grouped = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matched = (tools || []).filter(
      (t) => !q || t.name.toLowerCase().includes(q) || t.summary.toLowerCase().includes(q),
    );
    const groups = new Map<string, CapabilityTool[]>();
    for (const t of matched) {
      const list = groups.get(t.category) || [];
      list.push(t);
      groups.set(t.category, list);
    }
    return [...groups.entries()];
  }, [tools, query]);

  const total = tools?.length ?? 0;
  const shown = grouped.reduce((n, [, list]) => n + list.length, 0);

  return (
    <section className="panel stage-panel">
      <div className="panel-header">
        <div>
          <h1>Capabilities</h1>
          <p className="panel-kicker">
            {loading ? "loading…" : `${total} capabilities${query ? ` • ${shown} match` : ""}`}
          </p>
        </div>
        <button className="icon-button" type="button" onClick={() => void load()} title="Refresh">
          {loading ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
        </button>
      </div>

      <div className="stage-body capabilities-body">
        <div className="capabilities-search">
          <Search size={15} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search capabilities — wifi, osint, scan, crack…"
          />
        </div>

        {!loading && total === 0 ? (
          <p className="panel-kicker">No capabilities registered.</p>
        ) : null}

        {grouped.map(([category, list]) => (
          <div className="capability-group" key={category}>
            <h2 className="capability-group-title">
              {category} <span className="capability-group-count">{list.length}</span>
            </h2>
            <div className="capability-grid">
              {list.map((tool) => (
                <div className="capability-card" key={tool.name}>
                  <div className="capability-card-head">
                    <code className="capability-name">{tool.name}</code>
                    <button
                      type="button"
                      className="capability-ask"
                      title="Hand this to the agent"
                      onClick={() => onAskAgent(`Use the \`${tool.name}\` tool to `)}
                    >
                      <Send size={13} /> Ask agent
                    </button>
                  </div>
                  {tool.summary ? <p className="capability-summary">{tool.summary}</p> : null}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
