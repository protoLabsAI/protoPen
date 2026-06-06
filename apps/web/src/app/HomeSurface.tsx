import { ChevronRight } from "lucide-react";

import { chatStore, useChatState } from "../chat/chat-store";
import type { EngagementStatus } from "../lib/types";
import { STATE_LABEL, useCompanionState } from "./CompanionStatus";

// Home / Companion — the spine of the autonomous-first IA (vision doc, Slice 2).
// A glanceable presence band that answers "is it running, what's it doing, does
// it need me?" It sits above the chat steering channel — which App renders
// always-mounted (so a turn keeps streaming as you navigate), with Home just the
// presence hero. Consumes only existing data (engagement status + the chat
// store's HITL/stream state) — no new backend.

// One-line read on what the companion is doing right now, by state.
function subline(
  state: ReturnType<typeof useCompanionState>,
  eng: EngagementStatus | null,
): string {
  if (state === "offline") return "Disconnected from the runtime — reconnecting…";
  if (state === "waiting") return "Paused — it needs your input to continue.";
  if (state === "working") return "Working on a turn…";
  if (eng) return `Engagement live${eng.phase ? ` — ${eng.phase}` : ""}. Standing by.`;
  return "Standing by. Scope an engagement, or just start chatting below.";
}

function severityTone(severity?: string | null): string {
  const s = (severity || "").toLowerCase();
  if (s === "critical" || s === "high") return "error";
  if (s === "medium") return "warning";
  return "muted"; // low / info / missing / unknown
}

export function HomeSurface({
  engagement,
  live,
}: {
  engagement: EngagementStatus | null;
  live: boolean;
}) {
  const chat = useChatState();
  const state = useCompanionState(live);

  const eng = engagement?.active ? engagement : null;
  const mode = (eng?.mode || "").toLowerCase();
  const target = eng?.name || eng?.scope || "";

  // The first session parked on a HITL request — "Respond" switches to it so the
  // inline HitlForm (rendered by ChatSurface for the current session) comes into
  // view. We don't re-implement the form here; we route the operator to it.
  const waitingSessionId =
    Object.entries(chat.hitlPending).find(([, pending]) => pending)?.[0] ?? null;
  const waitingSession = waitingSessionId
    ? chat.sessions.find((session) => session.id === waitingSessionId) ?? null
    : null;

  // Most-recent findings first, capped — a glanceable ticker, not the full list
  // (that lives under Findings). Sort by timestamp when present, else keep order.
  const recentFindings = [...(eng?.findings ?? [])]
    .sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""))
    .slice(0, 5);

  return (
    <>
      <div className="home-hero panel" data-state={state} aria-live="polite">
        <div className="home-hero-row">
          <div className="home-hero-presence">
            <span className="companion-pulse" aria-hidden />
            <div className="home-hero-text">
              <div className="home-hero-state">{STATE_LABEL[state]}</div>
              <div className="home-hero-sub">{subline(state, eng)}</div>
            </div>
          </div>
          {eng ? (
            <div className="home-hero-engagement">
              <span className={`companion-mode mode-${mode}`}>{eng.mode}</span>
              {target ? (
                <span className="companion-target" title={eng.scope || target}>
                  {target}
                </span>
              ) : null}
              {eng.total_findings > 0 ? (
                <span className="companion-findings">
                  {eng.total_findings} finding{eng.total_findings === 1 ? "" : "s"}
                </span>
              ) : null}
            </div>
          ) : (
            <span className="companion-note">no engagement</span>
          )}
        </div>

        {waitingSession ? (
          <button
            type="button"
            className="home-needs-you"
            onClick={() => chatStore.switchSession(waitingSession.id)}
            title="Jump to the session that needs your input"
          >
            <span className="home-needs-dot" aria-hidden />
            <span className="home-needs-text">
              <strong>The companion needs you.</strong> “{waitingSession.title}” is waiting on your
              input.
            </span>
            <span className="home-needs-cta">
              Respond <ChevronRight size={14} />
            </span>
          </button>
        ) : null}

        {recentFindings.length > 0 ? (
          <div className="home-findings" aria-label="Recent findings">
            {recentFindings.map((finding, index) => (
              <div className="home-finding" key={`${finding.title}-${index}`}>
                <span className={`mini-dot tone-${severityTone(finding.severity)}`} />
                <span className="home-finding-title" title={finding.detail || finding.title}>
                  {finding.title}
                </span>
                {finding.category ? (
                  <span className="home-finding-cat">{finding.category}</span>
                ) : null}
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </>
  );
}
