import { useEffect, useState } from "react";

// Gamepad → intents (docs/plans/2026-07-22-chat-first-deck-ui.md, P3).
//
// In Game Mode the console runs as a non-Steam kiosk, so the Deck's controls
// arrive one of two ways depending on the Steam Input layout bound to it:
// as a real gamepad (this module) or as emulated keyboard/mouse (the shell's
// key bindings). Both funnel into the SAME intent vocabulary, so the shell only
// implements the behaviour once and neither path is the "real" one.
//
// Polling, not events: the Gamepad API only fires connect/disconnect events —
// button state must be sampled, so we run a rAF loop while a pad is attached
// (and nothing at all when none is).

export type Intent =
  | "up"
  | "down"
  | "left"
  | "right"
  | "confirm"
  | "back"
  | "prevTab"
  | "nextTab"
  | "composer"
  | "system"
  | "scrollUp"
  | "scrollDown";

type Handler = (intent: Intent) => void;

// Standard-mapping button indices (the Deck reports as a standard gamepad).
const BUTTON_INTENTS: Record<number, Intent> = {
  0: "confirm", // A
  1: "back", // B
  2: "composer", // X — jump to the composer (Steam's OSK is on its own binding)
  4: "prevTab", // L1
  5: "nextTab", // R1
  6: "scrollUp", // L2
  7: "scrollDown", // R2
  9: "system", // Start/Menu
  12: "up", // d-pad
  13: "down",
  14: "left",
  15: "right",
};

// Directions repeat while held (like a key); everything else is edge-triggered.
const REPEATABLE = new Set<Intent>(["up", "down", "left", "right", "scrollUp", "scrollDown"]);
const REPEAT_DELAY_MS = 380;
const REPEAT_RATE_MS = 110;
const DEADZONE = 0.55;

const handlers = new Set<Handler>();
let raf: number | null = null;
// Per-intent state: when it went down, and when we last emitted for it.
const held = new Map<Intent, { since: number; last: number }>();

function emit(intent: Intent) {
  handlers.forEach((handler) => handler(intent));
}

function pressedIntents(): Set<Intent> {
  const out = new Set<Intent>();
  const pads = navigator.getGamepads ? navigator.getGamepads() : [];
  for (const pad of pads) {
    if (!pad) continue;
    pad.buttons.forEach((button, index) => {
      if (!button?.pressed) return;
      const intent = BUTTON_INTENTS[index];
      if (intent) out.add(intent);
    });
    // Left stick doubles the d-pad — a thumb on the stick is the natural way to
    // move focus, and the Deck's d-pad is a stretch for a right-handed grip.
    const [x = 0, y = 0] = pad.axes;
    if (x <= -DEADZONE) out.add("left");
    if (x >= DEADZONE) out.add("right");
    if (y <= -DEADZONE) out.add("up");
    if (y >= DEADZONE) out.add("down");
    // Right stick scrolls the focused region.
    const ry = pad.axes[3] ?? 0;
    if (ry <= -DEADZONE) out.add("scrollUp");
    if (ry >= DEADZONE) out.add("scrollDown");
  }
  return out;
}

function tick(now: number) {
  const pressed = pressedIntents();
  for (const intent of pressed) {
    const state = held.get(intent);
    if (!state) {
      held.set(intent, { since: now, last: now });
      emit(intent);
      continue;
    }
    if (!REPEATABLE.has(intent)) continue;
    if (now - state.since < REPEAT_DELAY_MS) continue;
    if (now - state.last < REPEAT_RATE_MS) continue;
    state.last = now;
    emit(intent);
  }
  for (const intent of [...held.keys()]) {
    if (!pressed.has(intent)) held.delete(intent);
  }
  raf = window.requestAnimationFrame(tick);
}

function start() {
  if (raf === null) raf = window.requestAnimationFrame(tick);
}

function stop() {
  if (raf !== null) window.cancelAnimationFrame(raf);
  raf = null;
  held.clear();
}

/** Subscribe to gamepad intents. Polls only while a pad is connected. */
export function onGamepadIntent(handler: Handler): () => void {
  handlers.add(handler);
  const anyPad = () =>
    Boolean(navigator.getGamepads && Array.from(navigator.getGamepads()).some(Boolean));
  if (anyPad()) start();
  const onConnect = () => start();
  const onDisconnect = () => {
    if (!anyPad()) stop();
  };
  window.addEventListener("gamepadconnected", onConnect);
  window.addEventListener("gamepaddisconnected", onDisconnect);
  return () => {
    handlers.delete(handler);
    window.removeEventListener("gamepadconnected", onConnect);
    window.removeEventListener("gamepaddisconnected", onDisconnect);
    if (handlers.size === 0) stop();
  };
}

/** True once a gamepad is attached — the shell uses it to turn on the always-on
 *  focus ring (a pad user with an invisible caret is lost). `?nav=gamepad` forces
 *  it on for a Steam Input layout that emulates keyboard/mouse instead, where no
 *  pad ever connects. */
export function useGamepadPresent(): boolean {
  // `?nav=gamepad` PINS the mode on — for a Steam Input layout that emulates
  // keyboard/mouse, where no pad ever connects. Absent the override, presence
  // tracks whether a pad is actually attached, and goes back OFF when the last
  // one is unplugged: a pad user who switches to touch shouldn't be left with an
  // always-visible focus ring and the keyboard mirror still armed.
  const forced = (() => {
    try {
      return new URLSearchParams(window.location.search).get("nav") === "gamepad";
    } catch {
      return false; // malformed URL — fall through to the capability check
    }
  })();
  const anyPad = () =>
    Boolean(navigator.getGamepads && Array.from(navigator.getGamepads()).some(Boolean));
  const [present, setPresent] = useState(() => forced || anyPad());

  useEffect(() => {
    if (forced) {
      setPresent(true);
      return; // pinned on — nothing to track
    }
    const recompute = () => setPresent(anyPad());
    window.addEventListener("gamepadconnected", recompute);
    window.addEventListener("gamepaddisconnected", recompute);
    return () => {
      window.removeEventListener("gamepadconnected", recompute);
      window.removeEventListener("gamepaddisconnected", recompute);
    };
  }, [forced]);

  return present;
}
