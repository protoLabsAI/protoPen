---
outline: deep
---

# Steam Deck Setup

This tutorial takes you from a fresh SteamOS install to **pwnDeck** running as a
Game Mode app — autostarting on boot, configured in-browser with your own model
+ API key. No fleet account required.

The runtime is a rootful, `--privileged` podman container ([why](#why-a-container)).
The image bakes the whole toolchain — BlackArch tools, Python 3.12, and the
PortaPack-patched libhackrf — so you never strap repos or build from source on the
Deck, and nothing important lives on the immutable rootfs.

**Time:** ~15 minutes (plus a one-time image pull)

**Prerequisites:**
- Steam Deck with a fresh SteamOS install, connected to your network
- A workstation on the same network (for SSH — optional if you work on-device)
- An OpenAI-compatible API base + key for the agent (entered later, in the wizard)
- _(optional)_ a [Tailscale](https://tailscale.com) account for remote SSH

## 1. Enable SSH (optional)

Skip this if you'll work directly on the Deck in Desktop Mode. Otherwise, in
Desktop Mode → Konsole:

```bash
passwd                          # set a password for the deck user
sudo systemctl enable --now sshd
hostname -I                     # note the IP
```

From your workstation: `ssh deck@<DECK_IP>` (and `ssh-copy-id deck@<DECK_IP>` for
key auth).

## 2. Get the deck scripts

The app runs from the container image; you only need the repo for the `deck/`
install scripts:

```bash
git clone https://github.com/protoLabsAI/protoPen.git ~/protoPen
cd ~/protoPen
```

## 3. Bootstrap the host

`deck/bootstrap.sh` does the privileged host prep that a SteamOS atomic update
wipes — disabling the read-only rootfs, a validated passwordless-sudo rule, the
pacman keyring, and systemd linger. It's idempotent.

```bash
deck/bootstrap.sh
# or, for remote SSH that survives OS updates (binaries + state in /home):
deck/bootstrap.sh --with-tailscale
```

::: tip Re-run this after every SteamOS update
An OS update reimages the rootfs (re-enables read-only, wipes `/etc` + `/usr`).
Re-running `deck/bootstrap.sh` re-applies all of it in seconds. Everything else —
the container image, your config, your key, your art — lives in `/home` and is
untouched. See [Surviving SteamOS updates](#surviving-steamos-updates).
:::

With `--with-tailscale`, follow the printed `tailscale … up` URL once to
authenticate the node; it stays authenticated across reboots and updates.

## 4. Install the runtime

`deck/install.sh` pulls the runtime image from GHCR, sets up rootful podman
storage on `/home` (the default `/var` is only 230 MB), installs the
`systemd --user` unit, and **enables + starts** the container on `:7870`. The
container is the runtime — there is no separate "start" step.

```bash
deck/install.sh
```

No API key is needed up front — you'll enter yours in the setup wizard (step 6).
For the fleet gateway instead, see [Fleet / Infisical](#fleet-infisical-optional).

Verify it's serving:

```bash
curl -sf -o /dev/null -w '%{http_code}\n' http://localhost:7870/app/   # 200
```

## 5. Add to Game Mode

```bash
deck/install-deck-launcher.sh    # installs Chromium (flatpak) + the kiosk launcher
steamos-add-to-steam ~/.local/share/applications/protopen.desktop
deck/steam-art.sh                # optional: brand the library art
```

`steamos-add-to-steam` opens a Steam dialog — confirm it. Then **return to Game
Mode** (Steam → Power → Switch to Game Mode) and launch **pwnDeck** from your
library. The kiosk shows a "starting…" splash and switches to the console as soon
as the backend answers.

## 6. First run — the setup wizard

On first launch the console has no key, so the **setup wizard** opens
automatically:

1. **Identity** — name your agent + operator.
2. **Model Gateway** — enter your **API base** and **API key**, then **Probe** to
   list models and pick one.
3. **Persona / Tools / Workspace** — accept the defaults or tweak.
4. **Finish** — the wizard writes the config + key under `/sandbox` (mode `600`
   for the key) and reloads the agent.

Ask the agent something to confirm it answers. Your key is stored on the Deck only
(never in the image), so it survives image upgrades and OS updates.

## Surviving SteamOS updates {#surviving-steamos-updates}

After any SteamOS update, the only thing you need to do is re-apply the host prep:

```bash
cd ~/protoPen && deck/bootstrap.sh    # (add --with-tailscale if you use it)
```

Everything else persists because it lives in `/home`:

| Survives an OS update (in `/home`) | Wiped by an OS update (re-applied by `bootstrap.sh`) |
|---|---|
| container image + storage | read-only rootfs flag |
| `/sandbox` data, config, **your API key** | `/etc/sudoers.d` passwordless-sudo rule |
| systemd `--user` units + launcher | pacman keyring |
| Steam shortcut + library art | tailscale in `/usr` → reinstalled to `/home` by `--with-tailscale` |

## Fleet / Infisical (optional) {#fleet-infisical-optional}

To use the fleet LiteLLM gateway via an Infisical service token instead of a
BYO key, create the token drop-in and pass `--with-infisical`:

```bash
mkdir -p ~/.config/systemd/user/protopen.service.d
cat > ~/.config/systemd/user/protopen.service.d/infisical.conf <<'EOF'
[Service]
Environment=INFISICAL_TOKEN=<your-service-token>
EOF
deck/install.sh --with-infisical
```

An env/Infisical key always wins over the local wizard key, so a fleet Deck never
shows the wizard.

## Troubleshooting

| Issue | Fix |
|---|---|
| `podman pull` fails on read-only / sudo errors | Run `deck/bootstrap.sh` first (read-only disable + sudoers). |
| Container won't start | `systemctl --user status protopen-runtime.service` then `journalctl --user -u protopen-runtime.service -e`. |
| Storage error / `/var` full | Confirm rootful storage is on `/home`; `fuse-overlayfs` must be present (it ships with SteamOS). |
| Kiosk stays on the "starting…" splash | Backend isn't answering — check `curl localhost:7870/app/` and the unit status above. |
| Wizard never appears | A key is already configured (env/Infisical or a prior run). The wizard only shows when no key exists. |
| Agent turns 401 after setup | Wrong key/base, or the gateway lacks the chosen model. Re-open the wizard's Model step and re-Probe. |
| Setup says "restart to apply" | The in-process reload hit a snag but your config is saved — `systemctl --user restart protopen-runtime.service`. |
| Everything broke after a SteamOS update | Re-run `deck/bootstrap.sh`. |
| `tool_use ids without tool_result` errors | Corrupted session DB — `rm -f ~/.local/share/protopen-rt-data/knowledge/sessions.db*` and restart the unit. |

## Hardware: HackRF / PortaPack {#hackrf-portapack}

The runtime container bakes the **PortaPack-patched libhackrf** (Mayhem
enumerates as `1d50:6018`, which stock libhackrf ignores) and runs
`--privileged` with `/dev/bus/usb` passed through, so SDR works without any
host-side libhackrf build or udev rule. Two physical things still matter:

**Power** — the PortaPack draws ~500 mA. The official dock allocates 160–500 mA
per USB-A port and the device may fail to enumerate through it. **Connect directly
to the Deck's USB-C port**, or use a powered hub.

**Verify enumeration** on the host:

```bash
lsusb -d 1d50:6018    # → "Great Scott Gadgets PortaPack Mayhem"
```

No output usually means a charge-only cable or an under-powered port. Once it
enumerates, the agent's SDR tools (PortaPack capture, IMSI scan) reach it through
the container automatically. The Flipper/serial and WiFi-monitor-mode paths work
the same way (raw sockets + USB via `--privileged`).

::: tip Packet capture
tshark/dumpcap run inside the privileged container with the needed caps, so live
LAN capture (the `blackarch tshark_capture` / `net_monitor` tools) works out of
the box — no host `wireshark` group needed.
:::

## Why a container? {#why-a-container}

SteamOS is immutable: the rootfs is read-only and atomic updates wipe `/usr`,
`/etc`, the pacman state, and anything you installed there. A bare-metal install
(venv + pacman tools + a hand-built libhackrf) breaks on every OS update. Packing
the toolchain into an image that lives on `/home` — plus a one-command
`bootstrap.sh` for the handful of `/etc` bits an update resets — makes the setup
reproducible and update-proof.

## What's next

With pwnDeck running, continue to the [First Engagement](./first-engagement)
tutorial to run a passive network scan using only the Deck's built-in hardware.
