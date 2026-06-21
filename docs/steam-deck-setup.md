# protoPen — Steam Deck Quickstart

Fresh SteamOS → **pwnDeck** running as a Game Mode app, configured in-browser with
your own model + API key. The runtime is an update-proof `--privileged` container
(BlackArch tools, Python 3.12, and the PortaPack-patched libhackrf are baked in),
so there's no strapping repos or building from source on the Deck.

> For the full walkthrough — remote SSH, Game Mode kiosk, hardware (HackRF /
> PortaPack), surviving OS updates, and troubleshooting — see the
> [**Steam Deck Setup tutorial**](./tutorials/steam-deck-setup).

## TL;DR

In Desktop Mode → Konsole:

```bash
# (optional) remote access:  passwd && sudo systemctl enable --now sshd

git clone https://github.com/protoLabsAI/protoPen.git ~/protoPen
cd ~/protoPen

deck/bootstrap.sh              # privileged host prep — re-run after every OS update
                              #   (add --with-tailscale for update-proof remote SSH)
deck/install.sh               # pull the image + start the container on :7870
                              #   (add --with-infisical to use the fleet gateway)

deck/install-deck-launcher.sh                                   # kiosk + Chromium
steamos-add-to-steam ~/.local/share/applications/protopen.desktop
deck/steam-art.sh             # optional: brand the Steam library art
```

Return to Game Mode and launch **pwnDeck**. On first run the **setup wizard**
opens in-app — enter your API base + key, **Probe** for models, **Finish**, and
you're live. Your key is stored on the Deck under `/sandbox` (never in the image),
so it survives image upgrades and OS updates.

## After a SteamOS update

Re-run the host prep — that's the only thing an update resets:

```bash
cd ~/protoPen && deck/bootstrap.sh
```

Everything else (image, config, your key, Steam art) lives in `/home` and is
untouched. See the [tutorial](./tutorials/steam-deck-setup#surviving-steamos-updates)
for the full survives/wiped breakdown.
