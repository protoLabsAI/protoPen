import { useEffect, useState } from "react";

import { INTRO_HOLD_MS } from "./IntroSplash";

/**
 * pwnDeck launch bumper — the second frame, shown right after the
 * protoLabs.studio brand bumper (IntroSplash). Renders the pwnDeck wordmark as
 * ASCII art in the protoLabs lavender→indigo brand gradient
 * (`linear-gradient(135deg, #9b87f2, #818cf8, #6366f1)`, per protoContent's
 * brand.css), then cross-fades to the app via the View Transitions API.
 *
 * It sits at z-91 (above IntroSplash's z-90) and appears at exactly
 * INTRO_HOLD_MS on the same dark background, so the protoLabs → pwnDeck handoff
 * reads as a clean terminal-style frame swap. Skipped under automation, matching
 * IntroSplash.
 */

const PWN_HOLD_MS = 2000; // how long the pwnDeck frame holds before the app

// Exact wordmark — String.raw keeps the backslashes literal. Do not reformat.
const PWNDECK_ASCII = String.raw`                      ____            _
  _ ____      ___ __ |  _ \  ___  ___| | __
 | '_ \ \ /\ / / '_ \| | | |/ _ \/ __| |/ /
 | |_) \ V  V /| | | | |_| |  __/ (__|   <
 | .__/ \_/\_/ |_| |_|____/ \___|\___|_|\_\
 |_|`;

export function PwnDeckSplash() {
  // "wait" while the protoLabs bumper is up → "show" for our frame → "gone".
  const [phase, setPhase] = useState<"wait" | "show" | "gone">(() =>
    typeof navigator !== "undefined" && (navigator as Navigator).webdriver === true ? "gone" : "wait",
  );

  useEffect(() => {
    if (phase !== "wait") return; // automation-skip: nothing to schedule
    const show = window.setTimeout(() => setPhase("show"), INTRO_HOLD_MS);
    const done = window.setTimeout(() => {
      const doc = document as Document & {
        startViewTransition?: (cb: () => void) => unknown;
      };
      if (typeof doc.startViewTransition === "function") {
        // Cross-fade the bumper out and the app in; fall back to a plain unmount
        // so the splash can never get stuck on screen.
        try {
          doc.startViewTransition(() => setPhase("gone"));
        } catch {
          setPhase("gone");
        }
      } else {
        setPhase("gone");
      }
    }, INTRO_HOLD_MS + PWN_HOLD_MS);
    return () => {
      window.clearTimeout(show);
      window.clearTimeout(done);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (phase !== "show") return null;

  return (
    <div className="pwndeck-splash" role="img" aria-label="pwnDeck">
      <pre className="pwndeck-ascii" aria-hidden="true">
        {PWNDECK_ASCII}
      </pre>
    </div>
  );
}
