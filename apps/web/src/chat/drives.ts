import { useSyncExternalStore } from "react";

import { api } from "../lib/api";
import type { GoalState } from "../lib/types";

// Drives — a goal bound to a chat session, surfaced IN that session's tab
// (docs/plans/2026-07-22-chat-first-deck-ui.md, P2). Goals are keyed server-side
// by `session_id`, which is exactly the chat session id the console streams on,
// so no new binding is needed: a goal set with `/goal` in a tab already *is* that
// tab's drive. This store polls `/api/goals` once for the whole app and hands out
// per-session slices, so the chat header, the tab strip, and the Goals surface
// all read the same live state without N fetches.

const POLL_MS = 10_000;

let goals: GoalState[] = [];
let enabled = true;
let serialized = "[]"; // last payload, to keep object identity stable between polls
const listeners = new Set<() => void>();
let timer: number | null = null;
let inFlight = false;

function emit() {
  listeners.forEach((listener) => listener());
}

async function load() {
  if (inFlight) return;
  inFlight = true;

  try {
    const r = await api.goals();
    const next = JSON.stringify(r.goals || []);
    // Only swap the array when something actually changed — otherwise every poll
    // would hand `useSyncExternalStore` fresh objects and re-render the chat.
    if (next !== serialized || r.enabled !== enabled) {
      serialized = next;
      goals = r.goals || [];
      enabled = r.enabled;
      emit();
    }
  } catch {
    // Best-effort: a drive badge is not worth surfacing an error banner for.
  } finally {
    inFlight = false;
  }
}

// Don't poll a console nobody is looking at (the Deck sits on a shelf mid-drive);
// catch up in one fetch when it comes back.
function onVisibility() {
  if (!document.hidden) void load();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    void load();
    timer = window.setInterval(() => {
      if (!document.hidden) void load();
    }, POLL_MS);
    document.addEventListener("visibilitychange", onVisibility);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && timer !== null) {
      window.clearInterval(timer);
      timer = null;
      document.removeEventListener("visibilitychange", onVisibility);
    }
  };
}

/** Refetch now — call after anything that mutates goal state (a turn ending, a
 *  detach, a clear) so the UI doesn't wait out the poll interval. */
export function refreshDrives() {
  void load();
}

export function useDrives(): GoalState[] {
  return useSyncExternalStore(
    subscribe,
    () => goals,
    () => goals,
  );
}

/** False when goal mode is switched off in config — the surfaces say so rather
 *  than showing a permanently empty list. */
export function useDrivesEnabled(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => enabled,
    () => true,
  );
}

/** The goal driving this chat session, if any (including finished ones — an
 *  `achieved`/`exhausted` drive still deserves its badge until cleared). */
export function useDrive(sessionId: string): GoalState | null {
  const all = useDrives();
  return all.find((goal) => goal.session_id === sessionId) || null;
}

export function isActive(goal: GoalState | null | undefined): boolean {
  return Boolean(goal && goal.status === "active");
}
