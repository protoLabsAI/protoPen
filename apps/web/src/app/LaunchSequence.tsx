import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

import { ProtoLabsIcon } from "./ProtoLabsIcon";

/**
 * Two-frame launch sequence: the protoLabs.studio brand bumper, then the
 * pwnDeck wordmark, then the app.
 *
 * One coordinator (rather than two independent splashes) so the app is never
 * revealed between frames — frame 1 → frame 2 is a direct state swap on the
 * same dark background (a terminal-style frame change), and only the final
 * frame 2 → app uses the View Transitions API to cross-fade the app in. That
 * also avoids mounting frame 2 *during* frame 1's transition, which previously
 * flashed the app and clipped frame 2's background into a letterbox.
 *
 * Rendered through a portal to <body> so the full-screen `position: fixed`
 * overlay is always viewport-relative, never contained by a transformed
 * app-shell ancestor.
 *
 * Skipped under automation (navigator.webdriver) so the overlay doesn't
 * intercept E2E interactions.
 */

const BRAND_HOLD_MS = 2500; // protoLabs.studio bumper
const PWN_HOLD_MS = 3000; // pwnDeck bumper

// Exact wordmark — String.raw keeps the backslashes literal. Do not reformat.
const PWNDECK_ASCII = String.raw`                      ____            _
  _ ____      ___ __ |  _ \  ___  ___| | __
 | '_ \ \ /\ / / '_ \| | | |/ _ \/ __| |/ /
 | |_) \ V  V /| | | | |_| |  __/ (__|   <
 | .__/ \_/\_/ |_| |_|____/ \___|\___|_|\_\
 |_|`;

export function LaunchSequence() {
  const [phase, setPhase] = useState<"brand" | "pwndeck" | "done">(() =>
    typeof navigator !== "undefined" && (navigator as Navigator).webdriver === true ? "done" : "brand",
  );

  useEffect(() => {
    if (phase === "brand") {
      const t = window.setTimeout(() => setPhase("pwndeck"), BRAND_HOLD_MS);
      return () => window.clearTimeout(t);
    }
    if (phase === "pwndeck") {
      const t = window.setTimeout(() => {
        const doc = document as Document & {
          startViewTransition?: (cb: () => void) => unknown;
        };
        if (typeof doc.startViewTransition === "function") {
          // Cross-fade the bumper out and the app in; fall back to a plain
          // unmount so the splash can never get stuck on screen.
          try {
            doc.startViewTransition(() => setPhase("done"));
          } catch {
            setPhase("done");
          }
        } else {
          setPhase("done");
        }
      }, PWN_HOLD_MS);
      return () => window.clearTimeout(t);
    }
  }, [phase]);

  if (phase === "done" || typeof document === "undefined") return null;

  const frame =
    phase === "brand" ? (
      <div className="intro-splash" role="img" aria-label="protoLabs.studio">
        <div className="intro-splash-rise">
          <ProtoLabsIcon variant="outline" size={88} className="intro-splash-mark" decorative />
          <div className="intro-splash-word">protoLabs.studio</div>
        </div>
      </div>
    ) : (
      <div className="pwndeck-splash" role="img" aria-label="pwnDeck">
        <pre className="pwndeck-ascii" aria-hidden="true">
          {PWNDECK_ASCII}
        </pre>
      </div>
    );

  return createPortal(frame, document.body);
}
