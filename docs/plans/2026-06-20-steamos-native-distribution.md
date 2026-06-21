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

## On-device probe — 2026-06-20 (Phase 1, non-hardware half)

A read-only SSH probe of the Deck confirmed the container substrate and
**corrected two assumptions above**:

**Confirmed (de-risked):**

- **`podman 5.3.2` + `distrobox 1.8.0` are already installed** (SteamOS ships
  them). Rootless, overlay storage under
  `/home/deck/.local/share/containers/storage` → lives in `/home`, survives
  atomic updates. 407 GB free.
- **An Arch distrobox already exists on this Deck** — `archbuild`
  (`archlinux:latest`), the libhackrf-patch builder. The Arch-distrobox pattern
  is **already in the operator's workflow, not greenfield.**
- Built-in `wlan0` = `rtw_8822ce` (RTL8822CE); `phy0` advertises **`monitor`**
  mode → a possible hardware-light test path (caveat: flipping `wlan0` to
  monitor drops the Deck's own connectivity/SSH, so it's an on-device step, and
  rtw88 injection is flaky).
- protoPen is live on the Deck (`~/protoPen`, server HTTP 200 on `:7870`,
  bare-metal).

**Corrections:**

- **The existing `Dockerfile` is NOT the right runtime base.** It's Debian
  `python:3.12-slim`, runs **non-root** (drops to `sandbox`), and carries only
  the **OSINT subset** (maigret/holehe/phoneinfoga/agent-browser/chromium) + a
  partial pip list — **no BlackArch toolchain**. It's the fleet/production
  container, a different artifact. The Deck **runtime layer should be an
  Arch/BlackArch distrobox** (like the existing `archbuild`), `pacman`-installing
  the host's toolset and run `--privileged` + host netns; port the Dockerfile's
  OSINT-venv tricks into it. (The earlier "reuse the Dockerfile / ~80% built"
  framing was wrong for this layer.)
- **The host BlackArch layer is partial:** `aircrack-ng`/`airmon-ng`/`bettercap`/
  `nmap`/`tshark` present; `hcxdumptool`/`hashcat`/`hydra` **absent even
  bare-metal**. "~56 tools" is the catalog, not the installed reality.

**Still blocked (operator + hardware):** real monitor-mode/injection on the Alfa,
PortaPack/HackRF (patched libhackrf), and USB-rebind/serial (Flipper/Marauder) —
none of that hardware is currently attached (`lsusb`).

### Test distrobox built + validated (rootless, `protopen-test`)

Stood up a rootless Arch distrobox and ran the non-RF validation:

- **`pacman`-in-distrobox works.** Installed `nmap`/`tcpdump`/`bind`/`iproute2`/
  `aircrack-ng`(+`airmon-ng`)/`python`; all resolve. **This solves constraints #1
  and #2** — `pacman` the same Arch/BlackArch tools, they live in `/home`,
  survive atomic updates. (Cosmetic "Current root is not booted" + post-hook
  `execv` warnings are known distrobox-on-Arch noise; packages install fine.)
- **Rootless CANNOT do raw sockets / monitor mode.** `AF_PACKET SOCK_RAW` fails
  with `PermissionError` both as the user **and via `sudo`** (container-root in a
  rootless userns — caps are namespaced, don't apply to host interfaces). The
  bounding set lists `cap_net_admin`/`cap_net_raw` but the effective set is empty.
  → **The RF/raw-socket runtime needs a *rootful* distrobox** (`distrobox create
  --root` → `sudo podman`, real root in host netns, `--privileged`), or those
  specific ops stay host-side. Host netns *is* shared (`wlan0` is visible
  in-container, just not raw-manipulable rootless). `nmap -sT` connect scans work
  fine and see the live `:7870` from inside.
- **App substrate:** `~/protoPen` is visible in-container (shared `$HOME`); python
  present. ⚠️ Arch ships **python 3.14** — heavy deps (langgraph/gradio/
  sqlite-vec/a2a-sdk/PyMuPDF) may lack 3.14 wheels, so **the runtime image should
  pin a known-good python (e.g. 3.12)**, not ride Arch bleeding-edge. Full agent
  boot not attempted (needs venv build + gateway secret) — remaining increment.

**Revised GO/NO-GO (now hardware-gated):** create a **rootful `--privileged`**
distrobox, attach the Alfa + PortaPack, and confirm `airmon-ng` monitor mode +
`AF_PACKET` raw socket + USB rebind + patched-libhackrf work in-container.
Rootless is ruled out for the RF path.

### ✅ GO — monitor mode confirmed in a privileged container (Alfa attached)

With the Alfa (`AWUS036AXML`/`mt7921u` = `wlan1`/`phy1`) attached, a rootful
`sudo podman run --privileged --network host archlinux` container (storage
relocated to `/home`) **passed the WiFi/monitor-mode pillar end-to-end:**

- runs as **`uid=0(root)`** with full effective caps (`Current: =ep`) — vs.
  rootless `=` (empty);
- **`AF_PACKET SOCK_RAW` opens** (failed both ways rootless);
- a monitor vif on `phy1` (`iw phy phy1 interface add mon1 type monitor`, leaving
  `wlan1`/NM/SSH alone) + `tcpdump` **captured live 802.11 beacon frames** (5 GHz,
  real BSSIDs). The Alfa needed **no USB rebind**.

**Required runtime-layer setup conditions discovered:**

1. **Rootful podman storage must live on `/home`.** Partitions: `/` = 5.0 G
   (806 M free), `/var` = **230 M**, `/home` = 458 G (406 G free). Default
   `/var/lib/containers` can't hold an OS image (`no space left`). Use
   `--root /home/…` or `storage.conf` `graphroot`.
2. **overlay-over-ext4:** rootful logs `'overlay' is not supported over extfs` on
   `/home` — it falls back and runs, but configure **`fuse-overlayfs`** (mount
   program) for correctness/perf. (Rootless already uses fuse-overlayfs → why the
   earlier rootless box worked.)
3. **Config = real root + `--privileged` + `--network host`.** Rootless ruled out.
4. **OS-update survival:** the `/home` store survives atomic updates; the `/etc`
   `storage.conf` pointing to it must go in the keep-list.

### ✅ GO — PortaPack/HackRF (SDR) works in a privileged container

With the PortaPack Mayhem attached (`1d50:6018`, 500 mA), the same privileged
container passed the SDR pillar:

- PortaPack **visible in-container** (`-v /dev/bus/usb`);
- **stock** libhackrf 0.9.2 → "No HackRF boards found" (reproduces the `0x6018`
  patch requirement in-container);
- **patched** libhackrf 0.10.0 → **"Found HackRF"** + the expected Mayhem
  `hackrf_board_id_read() Pipe error` (normal).

**Runtime-layer note:** the patched libhackrf (`portapack_mayhem_usb_pid =
0x6018` in `libhackrf/src/hackrf.c`) must be **built into the image from source**
(`~/hackrf-portapack-src`). Doing so **retires the host-side
`reinstall.sh`-after-every-OS-update dance** — the patched lib lives in the
`/home` container, immune to atomic updates. (`build2`'s `cmake_install` bakes
absolute paths, so build fresh in the image rather than mounting a prebuilt tree.)

**Both RF pillars are GO in-container** (WiFi monitor mode + SDR).

### ✅ GO — Flipper serial passthrough works in a container

Flipper Zero "Lisazom" (`0483:5740` = `/dev/ttyACM1`; note `/dev/ttyACM0` is the
**Steam Deck Controller** — target the Flipper node only). A container with **only
`--device=/dev/ttyACM1`** (no `--privileged` needed) opened it via `pyserial` and
the Flipper CLI `device_info` returned `hardware_model: Flipper Zero`, firmware
`unlshd-071`, etc. The Marauder/WiFi-devboard rides this same serial path
(ESP32 Marauder app bridges UART — app-level, not a container concern).

### Phase 1 result: ✅ GO across all hardware pillars

| Pillar | Result |
|---|---|
| Container substrate (`podman`/`distrobox` preinstalled, in `/home`) | ✅ |
| `pacman` toolchain, survives atomic updates | ✅ |
| Rootless raw sockets / monitor mode | ❌ ruled out (caps namespaced) |
| **Rootful WiFi monitor mode** (Alfa) | ✅ captured live 802.11 |
| **Rootful SDR** (PortaPack/HackRF Mayhem) | ✅ patched libhackrf "Found HackRF" |
| **Serial** (Flipper Zero) | ✅ `device_info` over CLI |
| USB rebind | ✅ not needed — all devices enumerated directly |
| Full agent boot in-container | ⬜ runtime-image build work (pin python 3.12) |

The hardware de-risk is **complete**. The only unmet acceptance item (in-container
app boot) is mechanical build work — fold it into the runtime-layer image build.

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
