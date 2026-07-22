import { Loader2, LogOut, Radar, Square } from "lucide-react";
import { useState } from "react";

import { api } from "../lib/api";
import type { GoalState } from "../lib/types";
import { refreshDrives } from "./drives";

// The drive strip — the header of a chat tab that is DRIVING a goal
// (docs/plans/2026-07-22-chat-first-deck-ui.md, P2). It answers the three
// questions a running drive raises: what is it chasing, how far in is it, and
// how do I get out.
//
//   Detach — hand the loop to the scheduler; it keeps iterating with no console
//            attached, and the finished turn pushes back here over `chat.resumed`.
//   Stop   — clear the goal. The session stays; the agent stops looping.
//
// Rendered on desktop and handheld alike (one responsive codebase — the handheld
// rules only resize it).

function tone(status: string): string {
  if (status === "achieved") return "ok";
  if (status === "active") return "warning";
  return "error"; // exhausted | unachievable
}

export function DriveStrip({
  goal,
  onError,
}: {
  goal: GoalState;
  onError: (message: string) => void;
}) {
  const [busy, setBusy] = useState<"" | "detach" | "stop">("");
  const [note, setNote] = useState("");
  const active = goal.status === "active";
  const verifier = String((goal.verifier && goal.verifier.type) || "llm");

  async function detach() {
    setBusy("detach");
    try {
      const r = await api.detachGoal(goal.session_id);
      setNote(
        r.detached
          ? "Detached — driving headless. The next turn lands here when it finishes."
          : r.reason || "Nothing to detach.",
      );
      refreshDrives();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }

  async function stop() {
    setBusy("stop");
    try {
      await api.clearGoal(goal.session_id);
      setNote("Goal cleared — the agent stops looping after the current turn.");
      refreshDrives();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className={`drive-strip tone-${tone(goal.status)}`}>
      <div className="drive-line">
        <span className="drive-badge">
          <Radar size={14} />
          {goal.status === "active" ? "DRIVE" : goal.status.toUpperCase()}
        </span>
        <span className="drive-condition" title={goal.condition}>
          {goal.condition}
        </span>
        <span className="drive-meta">
          {goal.mode === "monitor" ? "monitor" : `${goal.iteration}/${goal.max_iterations}`} · {verifier}
        </span>
        {active ? (
          <div className="drive-actions">
            <button
              type="button"
              className="secondary-button drive-button"
              onClick={() => void detach()}
              disabled={busy !== ""}
              title="Hand the drive to the scheduler — it keeps working with this tab closed, and reports back here"
            >
              {busy === "detach" ? <Loader2 className="spin" size={14} /> : <LogOut size={14} />}
              Detach
            </button>
            <button
              type="button"
              className="secondary-button drive-button danger"
              onClick={() => void stop()}
              disabled={busy !== ""}
              title="Clear the goal — the agent stops looping"
            >
              {busy === "stop" ? <Loader2 className="spin" size={14} /> : <Square size={14} />}
              Stop
            </button>
          </div>
        ) : null}
      </div>
      {note || goal.last_reason ? <p className="drive-reason">{note || goal.last_reason}</p> : null}
    </div>
  );
}
