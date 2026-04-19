# protoPen — Steam Deck Setup Guide

Fresh SteamOS → SSH → BlackArch tools → protoPen installed → first test passing.

**Prerequisites:** Steam Deck with fresh SteamOS install, on the same network as your workstation.

---

## 1. Set a Password & Enable SSH

SteamOS ships with no password for the `deck` user and `sshd` disabled.

**On the Steam Deck** (Desktop Mode → Konsole):

```bash
# Set a password for the deck user
passwd

# Enable and start sshd
sudo systemctl enable sshd
sudo systemctl start sshd

# Grab the IP
hostname -I
```

**From your workstation:**

```bash
# Replace with your Deck's IP
ssh deck@<DECK_IP>
```

> **Tip:** For key-based auth (no password prompt), run from your workstation:
> ```bash
> ssh-keygen -t ed25519  # if you don't already have a key
> ssh-copy-id deck@<DECK_IP>
> ```

---

## 2. Disable Read-Only Filesystem & Configure Sudo

SteamOS mounts the root filesystem as read-only. We need to disable that first, then set up passwordless sudo for remote commands.

**On the Steam Deck** (run these manually — sudo needs a password the first time):

```bash
# Disable the read-only lock
sudo steamos-readonly disable

# Set up passwordless sudo (must load AFTER the wheel group rule)
echo 'deck ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/zz-deck
sudo chmod 0440 /etc/sudoers.d/zz-deck

# Initialize pacman keyring
sudo pacman-key --init
sudo pacman-key --populate archlinux
```

> **Why `zz-deck`?** SteamOS has `/etc/sudoers.d/wheel` which requires a password for the wheel group. Sudoers drop-in files are processed alphabetically — `zz-` ensures our NOPASSWD rule loads last and takes precedence.

> **Note:** SteamOS updates may re-enable the read-only lock and wipe `/etc/sudoers.d/zz-deck`. If `pacman` or sudo stops working after an update, re-run the commands above.

---

## 3. Install BlackArch Repository

Layer the BlackArch repo on top of SteamOS — this adds ~2800 pentest tools via `pacman` without replacing the OS.

```bash
# Download and run the BlackArch strap script
curl -fsSL https://blackarch.org/strap.sh -o /tmp/strap.sh

# Verify the SHA1 (check https://blackarch.org/downloads.html for current hash)
sha1sum /tmp/strap.sh

# Run it
chmod +x /tmp/strap.sh
sudo /tmp/strap.sh
```

Install the tools protoPen uses:

```bash
sudo pacman -Sy --noconfirm \
    nmap \
    aircrack-ng \
    bettercap \
    wireshark-cli
```

> **Note:** `tshark` is part of the `wireshark-cli` package on Arch.

Verify:

```bash
nmap --version
aircrack-ng --help 2>&1 | head -1
bettercap -version
tshark --version | head -1
```

---

## 4. Install Python & Git

SteamOS Holo ships with Python 3.13 and git pre-installed. Verify:

```bash
python --version  # Should be 3.12+
git --version
```

If Python is missing or too old:

```bash
sudo pacman -Sy --noconfirm python python-pip git base-devel
```

---

## 5. Install GitHub CLI

```bash
sudo pacman -Sy --noconfirm github-cli
```

Authenticate and set up git credential helper:

```bash
gh auth login
gh auth setup-git  # wires gh as git credential helper for HTTPS
```

> **Important:** Run `gh auth setup-git` — without it, `git clone` over HTTPS will fail with "could not read Username" since there's no interactive TTY in remote SSH sessions.

---

## 6. Clone & Install protoPen

```bash
# Clone (uses HTTPS via gh credential helper)
git clone https://github.com/protoLabsAI/protoPen.git ~/protoPen
cd ~/protoPen

# Create a venv
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

```

---

## 7. Run First Test

```bash
cd ~/protoPen
source .venv/bin/activate

# Run the full test suite
python -m pytest tests/ -v
```

**Expected output:**

```
1051 passed
```

If all 196 pass, protoPen is installed correctly and ready for hardware hookup.

---

## What's Next

Once tests pass, you can:

1. **Connect hardware** — Plug PortaPack directly into the Deck's USB-C port (not the hub — needs ~500mA); Flipper Zero and WiFi Marauder via hub is fine
2. **Verify devices** — `ls /dev/ttyACM* /dev/ttyUSB*` should show your serial devices; `hackrf_info` should show "Found HackRF"
3. **Update serial ports** — Edit `config/engagement-config.json` with actual device paths
4. **Start the agent** — `python server.py` (requires LLM gateway — see README.md)
5. **Run a passive scan** — Start an engagement in passive mode to verify hardware-in-the-loop works

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `pacman` fails with read-only errors | `sudo steamos-readonly disable` |
| `sudo` still asks for password | Check file is named `zz-deck` with `0440` perms: `ls -la /etc/sudoers.d/zz-deck` |
| BlackArch strap fails GPG check | `sudo pacman-key --refresh-keys` |
| `git clone` fails "could not read Username" | Run `gh auth setup-git` to wire credential helper |
| `git clone` fails "Host key verification" | Run `gh config set git_protocol https` to use HTTPS instead of SSH |
| Serial devices not showing up | Check USB connections, run `dmesg \| tail` for errors |
| `pip install` fails on `sqlite-vec` | Install build deps: `sudo pacman -S gcc cmake` |
| SteamOS update broke everything | Re-run steps 2-3 (read-only disable, sudoers, pacman keyring) |
| `hackrf_info` says "No HackRF boards found" | See [HackRF / PortaPack setup](./tutorials/steam-deck-setup#hackrf-portapack) — libhackrf needs patching for Mayhem firmware |
| PortaPack not enumerating at all | Connect directly to USB-C port; hub may not supply enough current |
