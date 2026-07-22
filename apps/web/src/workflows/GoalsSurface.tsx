import { Loader2, LogIn, RefreshCw, Sparkles, X } from "lucide-react";
import { useState } from "react";

import { api } from "../lib/api";
import { chatStore, useChatState } from "../chat/chat-store";
import { refreshDrives, useDrives, useDrivesEnabled } from "../chat/drives";
import type { ChatMessage, GoalState } from "../lib/types";

// Goals — the autonomy layer (top of the control stack). Goals are SET from chat
// with `/goal <condition>` and loop the agent toward a verifier (findings / llm)
// until met, exhausted, or unachievable.
//
// A goal is keyed by chat session, so it isn't really a list entry — it's a
// **drive** living in a chat tab (P2, docs/plans/2026-07-22-chat-first-deck-ui.md).
// This surface is where you find the ones you're NOT currently watching and
// ATTACH them: bind a chat tab to the goal's session (pulling its transcript from
// the checkpointer) so its turns — including a detached drive's — land in front
// of you.

function statusTone(status: string): string {
  if (status === "achieved") return "ok";
  if (status === "active") return "warning";
  return "error"; // exhausted | unachievable
}

export function GoalsSurface({
  onError,
  onOpenChat,
}: {
  onError: (message: string) => void;
  // Navigate to the chat surface (the console's Home / the handheld's Chat tab)
  // after attaching — attaching you can't see would be a no-op to the operator.
  onOpenChat?: () => void;
}) {
  const goals = useDrives();
  const enabled = useDrivesEnabled();
  const chat = useChatState();
  const [busy, setBusy] = useState(false);
  const [attaching, setAttaching] = useState("");
  // The chat sessions this browser already holds — a goal on one of them is
  // already attached, so it offers "Open" instead of "Attach".
  const localSessions = new Set(chat.sessions.map((session) => session.id));

  async function reload() {
    setBusy(true);
    try {
      refreshDrives();
    } finally {
      // The store swallows fetch errors (a badge isn't worth a banner); the spin
      // is cosmetic feedback that the refetch was kicked off.
      window.setTimeout(() => setBusy(false), 400);
    }
  }

  async function clear(sessionId: string) {
    try {
      await api.clearGoal(sessionId);
      refreshDrives();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  // Attach: adopt the goal's session id as a local chat tab, seeded with the
  // durable transcript so you see what already happened, not just what's next.
  async function attach(goal: GoalState) {
    setAttaching(goal.session_id);
    let messages: ChatMessage[] = [];
    try {
      const history = await api.chatHistory(goal.session_id);
      messages = (history.messages || []).map((m, i) => ({
        id: `attached-${goal.session_id}-${i}`,
        // Preserve the role rather than collapsing everything non-user to
        // assistant — ChatMessage allows "system", and mislabeling it would
        // misattribute a system line to the agent.
        role: m.role === "user" ? "user" : m.role === "system" ? "system" : "assistant",
        content: m.content,
        createdAt: Date.now(),
        status: "done" as const,
      }));
    } catch (e) {
      // An unreadable transcript shouldn't block attaching — the live turns are
      // the point. Say so rather than silently opening an empty tab.
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setAttaching("");
    }
    chatStore.attachSession(goal.session_id, goal.condition.slice(0, 52), messages);
    onOpenChat?.();
  }

  return (
    <section className="panel stage-panel">
      <div className="panel-header">
        <div>
          <h1>Goals</h1>
          <p className="panel-kicker">autonomy — each goal drives a chat session</p>
        </div>
        <button className="icon-button" type="button" onClick={() => void reload()} title="Refresh">
          {busy ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
        </button>
      </div>

      <div className="stage-body">
        {!enabled ? (
          <div className="empty-state stacked">
            <Sparkles size={18} />
            <span>Goal mode is disabled (set goals.enabled in config).</span>
          </div>
        ) : goals.length ? (
          <div className="goal-list">
            {goals.map((g) => {
              const vtype = String((g.verifier && g.verifier.type) || "llm");
              const local = localSessions.has(g.session_id);
              return (
                <article className="goal-card" key={`${g.session_id}:${g.condition}`}>
                  <div className="goal-head">
                    <span className={`goal-status tone-${statusTone(g.status)}`}>{g.status}</span>
                    <span className="goal-condition">{g.condition}</span>
                    <button
                      className="secondary-button drive-button"
                      type="button"
                      title={
                        local
                          ? "Open this drive's chat tab"
                          : "Attach — bind a chat tab to this drive and pull its transcript"
                      }
                      disabled={attaching === g.session_id}
                      onClick={() => void attach(g)}
                    >
                      {attaching === g.session_id ? (
                        <Loader2 className="spin" size={14} />
                      ) : (
                        <LogIn size={14} />
                      )}
                      {local ? "Open" : "Attach"}
                    </button>
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
