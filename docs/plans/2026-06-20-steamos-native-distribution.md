# Building & Distributing protoPen as a "Native SteamOS App"

> **Status: RESEARCH / proposal** (2026-06-20). This unparks the "native build"
> question from [`2026-06-04-steamdeck-ui.md`](./2026-06-04-steamdeck-ui.md)
> (parked 2026-06-05 pending the IA pass). It is a decision + architecture
> record, not yet a task-by-task plan. The original parking gate was *"native
> resumes only after IA settles"* — confirm that gate is cleared before
> executing Phase 1.

## TL;DR

"Native SteamOS app" conflates two different problems. For protoPen **the hard
part is not the UI shell — it's distributing a privileged, hardware-coupled
toolchain on an immutable OS.** The packaging models people usually *mean* by
"native app" (Flatpak from Discover/Flathub, or a Steam store title) are the
wrong fit and one is impossible.

**Recommended architecture — two layers:**

1. **Runtime layer** — ship the privileged backend + its ~56 BlackArch tools as a
   **distrobox / Podman container** (reuse the existing `Dockerfile`) that lives
   in `/home`, survives OS updates, and runs `--privileged` with host networking
   + device passthrough.
2. **UX layer** — a thin **Non-Steam Game launcher** that opens the web UI in a
   gamescope/Chromium kiosk with Steam Input, backed by a `systemd --user`
   service.

**Distribute it as a versioned container image (GHCR) + a one-shot `install.sh`**
— *not* as a Flathub/Discover/Steam package.

## Why "native app" is the wrong frame for protoPen

protoPen is **not a self-contained app**. It's a client/server stack — FastAPI on
`:7870` + a React SPA mounted at `/app/` (`server/app.py`) — that orchestrates
**~56 external BlackArch CLI binaries** (`aircrack-ng`, `airmon-ng`, `bettercap`,
`nmap`, `hcxdumptool`, `hashcat`, `tshark`, `frida`, `hydra`, `nuclei`, …) and
needs **raw sockets, monitor mode, USB/serial devices (Flipper, Marauder,
PortaPack/HackRF), SDR, and sudo**. Tauri was deliberately never ported
(comment in `server/app.py`: *"Webview-only: the Tauri desktop wrapper is
intentionally not ported"*), so there is no native wrapper to revive — it's
greenfield.

Any distribution plan must solve three things, in this priority order:

| # | Constraint | Why it dominates |
|---|---|---|
| **1** | **Toolchain + privilege** | ~56 system binaries + `CAP_NET_RAW`/`CAP_NET_ADMIN` + monitor mode + USB rebind. This is the whole product. |
| **2** | **Immutable-OS survival** | SteamOS atomic updates wipe pacman/BlackArch, `/etc/sudoers.d`, and `steamos-readonly disable`. Anything `pacman`-installed dies on every OS update. |
| **3** | **On-device UX** | Game Mode launch, controller + touch, 1280×800. |

## Options, scored against those three

### ❌ Flatpak / Flathub — *wrong fit; fails constraint #1*

This is what most people mean by "an installable native SteamOS app" (it's the
Discover store path). It does **not** work for protoPen. Per Flatpak's own
[sandbox-permissions docs](https://docs.flatpak.org/en/latest/sandbox-permissions.html):
the sandbox grants **no `CAP_NET_RAW`/`CAP_NET_ADMIN`** and "apps can't use
nonstandard network socket types" → **no raw sockets, no monitor mode, no packet
injection**. USB *can* be exposed (`--device=usb`/`all`), but the capability
restriction kills the core WiFi/network use case. On top of that, **none of the
56 BlackArch tools exist in any Flatpak runtime** — you'd have to rebuild the
entire pentest toolchain into the manifest, and **Flathub would not publish a
BlackArch wrapper** regardless. Dead end.

### ❌ Steam store (Steamworks) — *off the table*

That channel is for games and requires a partner agreement + content review. A
pentest tool won't pass and shouldn't apply. Named only because "native Steam
Deck app" gets conflated with "on Steam."

### 🟡 Non-Steam Game shortcut + kiosk UI — *cheapest "native feel," solves #3 only*

Add a shortcut that runs
`gamescope … chromium --kiosk --app=http://localhost:7870/app/`; it launches from
Game Mode with Steam Input driving the controller. The backend stays a normal
process with **full host access — exactly what protoPen needs.** This is the
right *UX* layer, but it punts #1/#2 to however the backend is installed.

### 🟡 Tauri / Electron / AppImage UI wrapper — *low ROI now*

Greenfield (Tauri un-ported) and only a window around the same web UI — does
nothing for the toolchain or immutable-OS problems. Skip until the UI itself is
settled.

### ✅ Distrobox / Podman container — *best answer for #1 and #2*

Per distrobox's [docs](https://github.com/89luca89/distrobox), it explicitly
targets **SteamOS3**, lives in `/home` (→ **survives atomic updates**), and gives
containers **host networking, full `/dev`/USB access, and privileged
operation**. Run the existing image `--privileged --network host` and you get
raw sockets/monitor mode + SDR/serial + all 56 tools in one update-resilient
bundle. The repo already has a multi-stage `Dockerfile` + `docker-compose.yml`,
so this is **~80% built**, and it retires the fragile "venv-in-`$HOME` + pacman/
BlackArch layering" model that today's `docs/steam-deck-setup.md` depends on.

## Recommended architecture (the build)

**Runtime layer.** Publish a versioned container image (GHCR) from the existing
`Dockerfile`. On the Deck, run it via distrobox/Podman with `--privileged`,
`--network host`, and device passthrough. This carries Python 3.11+ and the full
toolchain and is the thing that survives SteamOS updates.

**UX layer.** An `install.sh` that:

- pulls/creates the distrobox from the published image,
- drops a `systemd --user` unit to run the backend,
- installs a **Non-Steam launcher** (gamescope kiosk → `:7870/app/`) with Steam
  Input,
- fixes the PWA manifest (its `description` is **still stale protoAgent
  boilerplate** — "tracks the latest in AI/ML" — in `static/manifest.json`),
- registers any host-side files in
  `/etc/atomic-update.conf.d/protopen-keep.conf`.

## What "distribute" actually means here

protoPen is a niche, privileged security tool — there is **no app-store
distribution path**. "Distribution" = **reproducible install**:

- a **published, versioned container image** (GHCR) — the heavy artifact;
- a **one-shot `install.sh`** that automates `docs/steam-deck-setup.md` +
  launcher + keep-list (valuable independent of the UX tier);
- the setup doc already exists — fold it into the script and cut a versioned
  release.

## Phased plan

- **Phase 0 — Unpark + UI shape.** Confirm the IA gate is cleared. Resolve the
  still-open UI questions from the parked design doc (separate Deck surface vs.
  responsive; controller-nav model; v1 scope).
- **Phase 1 — Runtime de-risk (do this first).** Publish the image to GHCR;
  validate on the Deck that `distrobox --privileged --network host` actually
  delivers **monitor mode + USB/serial + the 56 tools**. This single experiment
  de-risks the entire approach (see Risks #1).
- **Phase 2 — Launcher.** `systemd --user` unit + Non-Steam gamescope kiosk
  shortcut + Steam Input; fix the manifest identity; confirm the kiosk targets
  `/app/` (React) not the Gradio root.
- **Phase 3 — Installer + release.** `install.sh` + atomic-update keep-list +
  docs; cut a versioned release.

## Risks to burn down on-device (so they're not re-discovered)

1. **Does `distrobox --privileged --network host` actually deliver monitor mode**
   for `airmon-ng`/`aircrack-ng` on the Alfa adapter? Memory notes USB-driver
   **rebind is permission-denied even with sudo** (needs `sudo -i` /
   readonly-disable), and the **patched libhackrf for the PortaPack Mayhem** is a
   host-side build. Containerizing may complicate both. **Prove this first — it's
   make-or-break.**
2. **Atomic-update survival** of remaining host-side bits (udev rules, patched
   libhackrf, keep-list).
3. **Controller-navigation model** for the UI is still unresolved (parked open
   question).
4. **Kiosk target** — confirm the launcher points at `/app/` (React console), not
   the Gradio root.

## Sources

- Flatpak sandbox permissions (capability/socket restrictions):
  <https://docs.flatpak.org/en/latest/sandbox-permissions.html>
- distrobox (immutable-OS / SteamOS3 support, host device + network access):
  <https://github.com/89luca89/distrobox>
- Repo state: `server/app.py`, `static/manifest.json`, `Dockerfile`,
  `docker-compose.yml`, `start.sh`, `docs/steam-deck-setup.md`,
  `config/engagement-config.json`.
