import { useSyncExternalStore } from "react";

// Is this a handheld/touch device (the Steam Deck, a phone, a tablet) rather than a
// mouse-driven desktop? We switch the console to the chat-first shell on **touch
// capability**, NOT viewport width — the Deck is 1280px wide (a "wide phone"), so any
// width breakpoint would misclassify it as a desktop and hand it the dense left-rail
// layout. `(hover: none) and (pointer: coarse)` is the capability signal: no hover, a
// coarse (finger) pointer. See docs/plans/2026-07-22-chat-first-deck-ui.md.
const QUERY = "(hover: none) and (pointer: coarse)";

// Dev/preview override: `?shell=handheld` or `?shell=desktop` forces the shell so the
// handheld layout can be exercised in an ordinary desktop browser (and pinned in the
// kiosk if the capability query ever misreports).
function forced(): boolean | null {
  if (typeof window === "undefined") return null;
  try {
    const v = new URLSearchParams(window.location.search).get("shell");
    if (v === "handheld") return true;
    if (v === "desktop") return false;
  } catch {
    // ignore a malformed URL — fall through to the capability query
  }
  return null;
}

function subscribe(onChange: () => void): () => void {
  if (typeof window === "undefined" || !window.matchMedia) return () => {};
  const mql = window.matchMedia(QUERY);
  // Safari <14 only has the deprecated addListener; guard for both.
  if (mql.addEventListener) {
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }
  mql.addListener(onChange);
  return () => mql.removeListener(onChange);
}

function getSnapshot(): boolean {
  const override = forced();
  if (override !== null) return override;
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia(QUERY).matches;
}

/** True on a touch handheld (Steam Deck / phone / tablet) — drives the chat-first shell. */
export function useIsHandheld(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, () => false);
}
