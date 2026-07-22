// Directional focus movement — the half of the gamepad model that decides
// "which control is *up* from here" (docs/plans/2026-07-22-chat-first-deck-ui.md, P3).
//
// A d-pad has no Tab order, so DOM order is the wrong answer: pressing Right on
// the thumb-nav should land on the next nav item, not on whatever happens to be
// next in the markup. We pick by geometry instead — the nearest focusable whose
// centre lies in the pressed direction, with cross-axis drift penalised so a
// control directly below always beats one that is closer but off to the side.

export type Direction = "up" | "down" | "left" | "right";

const FOCUSABLE = [
  "a[href]",
  "button:not(:disabled)",
  "input:not(:disabled)",
  "select:not(:disabled)",
  "textarea:not(:disabled)",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

// Cross-axis drift costs this many times its distance. High enough that a
// control in the pressed direction wins over a nearer one beside it.
const DRIFT_PENALTY = 2.5;
// Ignore sub-pixel jitter when deciding whether a candidate is really "up".
const EPSILON = 4;

function visible(el: Element): boolean {
  const rect = el.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return false;
  // offsetParent is null for display:none subtrees — which is how the console
  // hides inactive surfaces and non-visible chat slots.
  return (el as HTMLElement).offsetParent !== null;
}

/** Every focusable control currently on screen, in no particular order. */
export function focusables(root: ParentNode = document): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(visible);
}

function center(el: Element) {
  const r = el.getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
}

/** The best candidate in `direction` from `from`, or null if nothing lies that way. */
export function nextInDirection(
  from: HTMLElement | null,
  direction: Direction,
  candidates: HTMLElement[] = focusables(),
): HTMLElement | null {
  const pool = candidates.filter((el) => el !== from);
  if (pool.length === 0) return null;
  // Nothing focused yet (fresh page, or focus fell to <body>) — start somewhere
  // predictable rather than refusing to move.
  if (!from) return pool[0];

  const origin = center(from);
  let best: HTMLElement | null = null;
  let bestScore = Infinity;

  for (const el of pool) {
    const c = center(el);
    const dx = c.x - origin.x;
    const dy = c.y - origin.y;
    let along: number;
    let drift: number;
    if (direction === "up" || direction === "down") {
      along = direction === "up" ? -dy : dy;
      drift = Math.abs(dx);
    } else {
      along = direction === "left" ? -dx : dx;
      drift = Math.abs(dy);
    }
    if (along <= EPSILON) continue; // behind us, or level with us
    const score = along + drift * DRIFT_PENALTY;
    if (score < bestScore) {
      bestScore = score;
      best = el;
    }
  }
  return best;
}

/** Move focus one step. Returns true when focus actually moved. */
export function moveFocus(direction: Direction): boolean {
  const active = document.activeElement;
  const from = active instanceof HTMLElement && active !== document.body ? active : null;
  const target = nextInDirection(from, direction);
  if (!target) return false;
  target.focus();
  // Keep the newly focused control on screen inside whatever scroller holds it.
  target.scrollIntoView({ block: "nearest", inline: "nearest" });
  return true;
}

/** The nearest scrollable ancestor of the focused element (or the message list) —
 *  what the right stick / triggers scroll. */
export function scrollContainer(): HTMLElement | null {
  let el = document.activeElement as HTMLElement | null;
  while (el && el !== document.body) {
    const style = window.getComputedStyle(el);
    const scrolls = /(auto|scroll)/.test(style.overflowY);
    if (scrolls && el.scrollHeight > el.clientHeight + 4) return el;
    el = el.parentElement;
  }
  return document.querySelector<HTMLElement>(".chat-session-slot:not([hidden]) .message-list");
}
