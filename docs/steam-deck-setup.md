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

# Grab the IP for SSH from your workstation
ip addr show | grep 'inet ' | grep -v 127.0.0.1
```

**From your workstation:**

```bash
# Replace with your Deck's IP
ssh deck@<DECK_IP>
```

> **Tip:** For key-based auth (no password prompt), run from your workstation:
> ```bash
> ssh-copy-id deck@<DECK_IP>
> ```

---

## 2. Disable Read-Only Filesystem

SteamOS mounts the root filesystem as read-only by default. BlackArch repo setup requires `pacman`, which needs a writable root.

```bash
# Disable the read-only lock
sudo steamos-readonly disable

# Initialize pacman keyring (may already be done)
sudo pacman-key --init
sudo pacman-key --populate archlinux
```

> **Note:** SteamOS updates may re-enable the read-only lock. If `pacman` stops working after an update, run `sudo steamos-readonly disable` again.

---

## 3. Install BlackArch Repository

Layer the BlackArch repo on top of SteamOS — this adds ~2800 pentest tools available through `pacman` without replacing the OS.

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
    tshark
```

Verify:

```bash
nmap --version
aircrack-ng --help 2>&1 | head -1
bettercap -version
tshark --version | head -1
```

---

## 4. Install Python 3.12 & Git

SteamOS may ship with an older Python. Ensure we have 3.12+ and git:

```bash
sudo pacman -Sy --noconfirm python python-pip git base-devel
python --version  # Should be 3.12+
```

If SteamOS's pacman ships Python < 3.12, use pyenv:

```bash
# Install pyenv
curl https://pyenv.run | bash

# Add to shell (append to ~/.bashrc)
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc

# Install and set Python 3.12
pyenv install 3.12
pyenv global 3.12
python --version
```

---

## 5. Install GitHub CLI

```bash
sudo pacman -Sy --noconfirm github-cli
```

If `github-cli` isn't available in the repos:

```bash
# Install from official tarball
GH_VERSION=$(curl -s https://api.github.com/repos/cli/cli/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//')
curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" \
    | sudo tar xz -C /usr/local --strip-components=1
gh --version
```

Authenticate:

```bash
gh auth login
```

---

## 6. Clone & Install protoPen

```bash
# Clone with submodules
gh repo clone protoLabsAI/protoPen ~/protoPen
cd ~/protoPen
git submodule update --init --recursive

# Create a venv
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install the nanobot submodule
pip install ./nanobot/
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
187 passed, 9 skipped
```

The 9 skips are integration tests that require a running LLM gateway — expected on a fresh setup.

If all 187 pass, protoPen is installed correctly and ready for hardware hookup.

---

## What's Next

Once tests pass, you can:

1. **Connect hardware** — Plug in PortaPack, Flipper Zero, and WiFi Marauder via USB hub
2. **Verify devices** — `ls /dev/ttyACM* /dev/ttyUSB*` should show your serial devices
3. **Update serial ports** — Edit `config/engagement-config.json` with actual device paths
4. **Start the agent** — `python server.py` (requires LLM gateway — see README.md)
5. **Run a passive scan** — Start an engagement in passive mode to verify hardware-in-the-loop works

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `pacman` fails with read-only errors | `sudo steamos-readonly disable` |
| BlackArch strap fails GPG check | `sudo pacman-key --refresh-keys` |
| `python` not found after pyenv install | `source ~/.bashrc` or restart shell |
| Serial devices not showing up | Check USB connections, run `dmesg \| tail` for errors |
| `pip install` fails on `sqlite-vec` | Install build deps: `sudo pacman -S gcc cmake` |
| Tests import error on `pyudev` | Expected on non-Linux or if pyudev not installed — it's optional |
