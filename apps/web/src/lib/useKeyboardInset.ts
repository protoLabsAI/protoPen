import { useEffect } from "react";

// Keep the chat composer above the on-screen keyboard on touch devices. When the
// soft keyboard opens, the visual viewport shrinks; we expose the covered height as
// a `--kb-inset` CSS variable so the chat surface can pad above it. Chromium (the
// Deck kiosk) also honors `interactive-widget=resizes-content` in the viewport meta,
// which resizes the layout viewport directly — this hook covers browsers that don't
// (and is a harmless no-op where `visualViewport` is unavailable). See
// docs/plans/2026-07-22-chat-first-deck-ui.md (P1).
export function useKeyboardInset(): void {
  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;
    const root = document.documentElement;
    const update = () => {
      // Height hidden below the visual viewport = the keyboard's footprint.
      const inset = Math.max(0, window.innerHeight - vv.height - vv.offsetTop);
      root.style.setProperty("--kb-inset", `${Math.round(inset)}px`);
    };
    update();
    vv.addEventListener("resize", update);
    vv.addEventListener("scroll", update);
    return () => {
      vv.removeEventListener("resize", update);
      vv.removeEventListener("scroll", update);
      root.style.removeProperty("--kb-inset");
    };
  }, []);
}
