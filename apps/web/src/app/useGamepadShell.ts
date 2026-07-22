import { useEffect, useRef } from "react";

import { onGamepadIntent, type Intent } from "../lib/gamepad";
import { moveFocus, scrollContainer, type Direction } from "../lib/spatialNav";

// Binds gamepad intents to the console shell — the Game Mode half of the
// chat-first Deck UI (docs/plans/2026-07-22-chat-first-deck-ui.md, P3).
//
// The Deck in Game Mode has no cursor unless the operator drags a trackpad, so
// the shell has to be *drivable*: a moving focus ring, A to act, B to back out,
// bumpers to change surface. Intents come from a real gamepad (lib/gamepad) or,
// when the bound Steam Input layout emulates keyboard/mouse instead, from the
// arrow/Escape keys — the same handler serves both.
//
// Deliberately conservative: the key bindings only exist while gamepad mode is
// on, and never while the operator is typing, so a desktop keyboard is untouched.

const DIRECTIONS: Record<string, Direction> = {
  up: "up",
  down: "down",
  left: "left",
  right: "right",
};

const SCROLL_STEP = 120;

function isTyping(): boolean {
  const el = document.activeElement;
  if (!el) return false;
  const tag = el.tagName;
  return tag === "TEXTAREA" || tag === "INPUT" || (el as HTMLElement).isContentEditable;
}

export function useGamepadShell({
  enabled,
  surfaces,
  surface,
  setSurface,
}: {
  enabled: boolean;
  // Surfaces the bumpers cycle through, in thumb-nav order.
  surfaces: string[];
  surface: string;
  setSurface: (surface: string) => void;
}) {
  // Keep the handler's view of the shell current without re-subscribing (and
  // restarting the poll loop) on every surface change.
  const ref = useRef({ surfaces, surface, setSurface });
  ref.current = { surfaces, surface, setSurface };

  useEffect(() => {
    if (!enabled) return;

    function handle(intent: Intent) {
      const { surfaces, surface, setSurface } = ref.current;

      const direction = DIRECTIONS[intent];
      if (direction) {
        // While the composer holds focus, ALL directions belong to the caret
        // (native arrows move within the multi-line textarea) — not to focus
        // movement, which would yank you out of a half-written message. Up/Down
        // are line moves just as much as Left/Right are char moves, so guard
        // every direction, not just the horizontal pair. B (back) is the
        // deliberate way out of the composer.
        if (isTyping()) return;
        moveFocus(direction);
        return;
      }

      switch (intent) {
        case "confirm": {
          const el = document.activeElement;
          if (el instanceof HTMLElement) el.click();
          return;
        }
        case "back": {
          // A dialog owns Back first — backing out of a confirm must not also
          // navigate the surface underneath it.
          const cancel = document.querySelector<HTMLElement>(".confirm-overlay .secondary-button");
          if (cancel) {
            cancel.click();
            return;
          }
          if (isTyping()) {
            (document.activeElement as HTMLElement).blur();
            return;
          }
          // Anywhere but chat, Back dismisses the pushed-over surface. On chat it
          // is a no-op — there is nothing behind chat; it IS the root.
          if (surface !== "home") setSurface("home");
          return;
        }
        case "prevTab":
        case "nextTab": {
          const index = surfaces.indexOf(surface);
          const step = intent === "nextTab" ? 1 : -1;
          // Cycle, so the bumpers never dead-end on the first/last surface.
          const next = surfaces[(((index < 0 ? 0 : index) + step) + surfaces.length) % surfaces.length];
          setSurface(next);
          return;
        }
        case "composer": {
          setSurface("home");
          // The composer lives in the visible chat slot; the surface swap above
          // may not have painted yet, so focus on the next frame.
          window.requestAnimationFrame(() => {
            document
              .querySelector<HTMLTextAreaElement>(".chat-session-slot:not([hidden]) .composer textarea")
              ?.focus();
          });
          return;
        }
        case "system":
          setSurface(surface === "system" ? "home" : "system");
          return;
        case "scrollUp":
        case "scrollDown":
          scrollContainer()?.scrollBy({
            top: intent === "scrollDown" ? SCROLL_STEP : -SCROLL_STEP,
            behavior: "auto",
          });
          return;
      }
    }

    const unsubscribe = onGamepadIntent(handle);

    // Keyboard mirror — for a Steam Input layout that sends keys instead of pad
    // buttons (and for driving the same model from a real keyboard on the Deck).
    function onKey(event: KeyboardEvent) {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      const typing = isTyping();
      switch (event.key) {
        case "ArrowUp":
        case "ArrowDown":
        case "ArrowLeft":
        case "ArrowRight":
          if (typing) return; // never fight the caret
          event.preventDefault();
          handle(DIRECTIONS[event.key.replace("Arrow", "").toLowerCase()]);
          return;
        case "Escape":
          // ConfirmDialog binds Escape itself; don't double-handle it.
          if (document.querySelector(".confirm-overlay")) return;
          handle("back");
          return;
        case "PageUp":
          if (typing) return;
          handle("scrollUp");
          return;
        case "PageDown":
          if (typing) return;
          handle("scrollDown");
          return;
      }
    }
    window.addEventListener("keydown", onKey);

    return () => {
      unsubscribe();
      window.removeEventListener("keydown", onKey);
    };
  }, [enabled]);
}
