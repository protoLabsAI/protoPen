#!/usr/bin/env bash
# pwnDeck — Game Mode kiosk launcher.
# Opens the operator console fullscreen in a Chromium kiosk. Added to Steam as a
# Non-Steam game (steamos-add-to-steam) so it launches from Game Mode with Steam
# Input. Tracker: protopen-3t5.2.
#
# Backend: the container runtime on :7870. On a cold Game Mode boot the backend
# may still be starting (or pulling a fresh image), so instead of pointing
# Chromium straight at the app — which would flash a connection error — we open a
# local splash that polls the backend and redirects the moment it answers (or
# after a hard cap, by which point it's surely up). Override the target with
# PROTOPEN_URL.
set -u

URL="${PROTOPEN_URL:-http://localhost:7870/app/}"
PROFILE="${PROTOPEN_KIOSK_PROFILE:-$HOME/.protopen-kiosk-profile}"
SPLASH="${XDG_RUNTIME_DIR:-/tmp}/pwndeck-splash.html"

# Branded "starting…" splash. It does ALL the waiting (Chromium opens instantly),
# polling the backend with an opaque no-cors fetch and replacing itself with the
# app as soon as the request resolves; a ~3 min hard cap navigates anyway so a
# blocked probe can never strand the kiosk on the splash.
cat >"$SPLASH" <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>pwnDeck</title>
<style>
  :root { --green: #3ee07a; }
  html, body { height: 100%; margin: 0; }
  body {
    background: #0b0f0d; color: var(--green);
    font-family: "JetBrains Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 1.5rem; letter-spacing: 0.06em;
  }
  .mark { font-size: 2.6rem; font-weight: 700; }
  .mark::before { content: "> "; opacity: 0.6; }
  .status { font-size: 0.95rem; opacity: 0.8; }
  .dots::after { content: ""; animation: dots 1.4s steps(4, end) infinite; }
  @keyframes dots { 0% { content: ""; } 25% { content: "."; } 50% { content: ".."; } 75% { content: "..."; } }
  .bar { width: 220px; height: 3px; background: rgba(62,224,122,0.15); overflow: hidden; border-radius: 2px; }
  .bar > span { display: block; height: 100%; width: 40%; background: var(--green);
    animation: slide 1.2s ease-in-out infinite; }
  @keyframes slide { 0% { transform: translateX(-100%); } 100% { transform: translateX(350%); } }
</style>
</head>
<body>
  <div class="mark">pwnDeck</div>
  <div class="bar"><span></span></div>
  <div class="status">starting the operator console<span class="dots"></span></div>
<script>
  const target = new URLSearchParams(location.search).get("to") || "http://localhost:7870/app/";
  let tries = 0;
  async function poll() {
    tries++;
    try {
      await fetch(target, { mode: "no-cors", cache: "no-store" });
      location.replace(target);
      return;
    } catch (e) { /* backend not up yet */ }
    if (tries > 120) { location.replace(target); return; } // ~3 min cap: just go
    setTimeout(poll, 1500);
  }
  poll();
</script>
</body>
</html>
HTML

mkdir -p "$PROFILE"
exec flatpak run org.chromium.Chromium \
    --kiosk --app="file://$SPLASH?to=$URL" \
    --user-data-dir="$PROFILE" \
    --no-first-run --no-default-browser-check \
    --disable-features=Translate \
    --ozone-platform-hint=auto
