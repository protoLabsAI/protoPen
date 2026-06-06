import type { EngagementStatus } from "../lib/types";
import { useChatState } from "../chat/chat-store";

// The companion "presence" — a glanceable, terminal-styled read on what the
// agent is doing right now, plus the live engagement (mode / target / findings).
// The autonomous-first vision's "face" beat, on-brand (a pulse, not a cartoon).
// State precedence: offline → waiting-on-you (a HITL pause) → working → idle.

export type CompanionState = "offline" | "waiting" | "working" | "idle";

export const STATE_LABEL: Record<CompanionState, string> = {
  offline: "Offline",
  waiting: "Waiting on you",
  working: "Working",
  idle: "Idle",
};

// Shared precedence so the topbar strip and the Home hero (Slice 2) can't drift.
export function useCompanionState(live: boolean): CompanionState {
  const chat = useChatState();
  const waiting = Object.values(chat.hitlPending).some(Boolean);
  const working = Object.values(chat.sessionStatusMap).some((status) => status === "streaming");
  return !live ? "offline" : waiting ? "waiting" : working ? "working" : "idle";
}

export function CompanionStatus({
  engagement,
  live,
}: {
  engagement: EngagementStatus | null;
  live: boolean;
}) {
  const state = useCompanionState(live);

  const eng = engagement?.active ? engagement : null;
  const mode = (eng?.mode || "").toLowerCase();
  const target = eng?.name || eng?.scope || "";

  return (
    <div className="companion" data-state={state} aria-live="polite">
      <span className="companion-pulse" aria-hidden />
      <span className="companion-state">{STATE_LABEL[state]}</span>
      {eng ? (
        <>
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
        </>
      ) : (
        <span className="companion-note">no engagement</span>
      )}
    </div>
  );
}
