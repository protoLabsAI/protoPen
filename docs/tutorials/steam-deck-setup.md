---
outline: deep
---

# Steam Deck Setup

This tutorial takes you from a fresh SteamOS install to a fully working protoPen installation with the server running as a systemd user service. By the end, protoPen will start automatically on boot and be reachable over Tailscale SSH.

**Time:** ~30 minutes

**Prerequisites:**
- Steam Deck with a fresh SteamOS install, connected to your network
- A workstation on the same network (for SSH access)
- An [Infisical](https://infisical.com) account with access to the protoPen project secrets

## 1. Enable SSH

SteamOS ships with no password and `sshd` disabled. You need to fix both.

**On the Steam Deck** — switch to Desktop Mode, open Konsole, and run:

```bash
# Set a password for the deck user
passwd

# Enable and start the SSH daemon
sudo systemctl enable sshd
sudo systemctl start sshd

# Grab your IP for the next step
hostname -I
```

**From your workstation**, verify you can connect:

```bash
ssh deck@<DECK_IP>
```

::: tip Key-based auth
Set up SSH keys now so you never need the password again:

```bash
ssh-keygen -t ed25519            # skip if you already have a key
ssh-copy-id deck@<DECK_IP>
```
:::

Once Tailscale is installed (later in this guide), you will connect via:

```bash
ssh deck@steamdeck
```

## 2. Disable the read-only filesystem

SteamOS mounts root as read-only. We need to disable this and configure passwordless sudo for remote commands.

```bash
# Disable the read-only lock
sudo steamos-readonly disable

# Set up passwordless sudo
echo 'deck ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/zz-deck
sudo chmod 0440 /etc/sudoers.d/zz-deck

# Initialize the pacman keyring
sudo pacman-key --init
sudo pacman-key --populate archlinux
```

::: warning SteamOS updates
SteamOS updates may re-enable the read-only lock and wipe `/etc/sudoers.d/zz-deck`. If `pacman` or passwordless `sudo` stops working after an update, re-run the commands above.
:::

**Why `zz-deck`?** SteamOS has `/etc/sudoers.d/wheel` which requires a password. Sudoers drop-in files load alphabetically — `zz-` ensures the NOPASSWD rule wins.

## 3. Install BlackArch repository

BlackArch layers ~2800 pentest tools on top of SteamOS via `pacman` without replacing the OS.

```bash
# Download and run the strap script
curl -fsSL https://blackarch.org/strap.sh -o /tmp/strap.sh

# Verify the SHA1 hash (check https://blackarch.org/downloads.html for the current value)
sha1sum /tmp/strap.sh

# Install
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

Verify everything installed:

```bash
nmap --version
bettercap -version
tshark --version | head -1
```

::: tip
`tshark` is part of the `wireshark-cli` package on Arch.
:::

## 4. Install Python, Git, and GitHub CLI

SteamOS Holo ships with Python 3.13 and git pre-installed. Verify:

```bash
python --version   # needs 3.12+
git --version
```

If Python is missing or too old:

```bash
sudo pacman -Sy --noconfirm python python-pip git base-devel
```

Install GitHub CLI and authenticate:

```bash
sudo pacman -Sy --noconfirm github-cli

gh auth login
gh auth setup-git
```

::: warning
You **must** run `gh auth setup-git` — without it, `git clone` over HTTPS will fail with "could not read Username" since there is no interactive TTY in remote SSH sessions.
:::

## 5. Install Tailscale

Tailscale provides the stable SSH connection between your workstation and the Deck, regardless of what WiFi network either device is on.

```bash
sudo pacman -Sy --noconfirm tailscale

sudo systemctl enable tailscaled
sudo systemctl start tailscaled

sudo tailscale up --ssh
```

Follow the auth URL printed to the terminal. Once authenticated, you can reach the Deck from any device on your tailnet:

```bash
ssh deck@steamdeck
```

## 6. Clone and install protoPen

```bash
git clone https://github.com/protoLabsAI/protoPen.git ~/protoPen
cd ~/protoPen
git submodule update --init --recursive

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install the nanobot submodule
pip install ./nanobot/
```

::: tip Build errors on sqlite-vec
If `pip install` fails on `sqlite-vec`, install the build toolchain first:

```bash
sudo pacman -S --noconfirm gcc cmake
```
:::

Run the test suite to verify the install:

```bash
cd ~/protoPen
source .venv/bin/activate
python -m pytest tests/ -v
```

All 196 tests should pass.

## 7. Install Infisical CLI and configure service token

protoPen fetches secrets at runtime from Infisical — no `.env` files on disk. Install the CLI:

```bash
curl -1sLf 'https://artifacts.infisical.com/repos/infisical/setup.rpm.sh' | sudo -E bash
sudo pacman -Sy --noconfirm infisical
```

### Create a service token

`start.sh` uses an `INFISICAL_TOKEN` service token for non-interactive auth (no `infisical login` required). Create a token in the Infisical dashboard for the **protoPen** project (`f7d3c43d-be5e-4a05-ac4c-c69d1e09d6c7`), scoped to the **prod** environment.

### Inject the token via systemd override

Store the token in a systemd drop-in so it is available at boot without touching disk in the repo:

```bash
mkdir -p ~/.config/systemd/user/protopen.service.d

cat > ~/.config/systemd/user/protopen.service.d/infisical.conf << 'EOF'
[Service]
Environment=INFISICAL_TOKEN=<your-service-token>
EOF

systemctl --user daemon-reload
```

### Verify secrets fetch

```bash
INFISICAL_TOKEN=<your-service-token> infisical export \
    --domain https://secrets.proto-labs.ai/api \
    --env prod \
    --format dotenv \
    --silent \
    --token "$INFISICAL_TOKEN"
```

You should see all project secrets (including `LITELLM_MASTER_KEY`, `ANTHROPIC_API_KEY`, etc.). `start.sh` exports **all** Infisical secrets into the process environment automatically — no need to cherry-pick individual keys.

::: warning Zero env-on-disk policy
protoPen never writes API keys or secrets to disk. The `start.sh` launcher fetches secrets from Infisical into environment variables at boot and they exist only in process memory. The only exception is the `INFISICAL_TOKEN` in the systemd override, which lives outside the repo at `~/.config/systemd/user/protopen.service.d/infisical.conf`.
:::

## 8. Create the /sandbox symlink

protoPen stores knowledge, audit logs, and papers under `/sandbox`. On bare metal (no Docker), this needs to be a symlink to a local data directory:

```bash
mkdir -p ~/protoPen/data/knowledge ~/protoPen/data/audit ~/protoPen/data/intel ~/protoPen/data/lab
sudo ln -sfn ~/protoPen/data /sandbox
```

## 9. Create a systemd user service

A systemd user service starts protoPen automatically on boot without requiring a login session.

Create the service file:

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/protopen.service << 'EOF'
[Unit]
Description=protoPen — autonomous pen-testing agent
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/deck/protoPen
ExecStart=/home/deck/protoPen/start.sh --port 7870
Restart=on-failure
RestartSec=10
Environment=AGENT_BACKEND=langgraph

[Install]
WantedBy=default.target
EOF
```

Enable and start it:

```bash
systemctl --user daemon-reload
systemctl --user enable protopen.service
systemctl --user start protopen.service
```

Check that it is running:

```bash
systemctl --user status protopen.service
```

## 10. Enable linger

By default, systemd user services only run while the user has an active login session. Linger keeps them running after you disconnect SSH:

```bash
sudo loginctl enable-linger deck
```

## 11. Set Desktop Mode as default boot target

protoPen runs headless — you do not need Game Mode. Setting Desktop Mode as the default avoids wasting resources on the Steam client:

```bash
sudo steamos-session-select plasma-persistent
```

The Deck will now boot directly into KDE Plasma desktop.

## 12. Verify the server

From your workstation, check that the server is reachable:

```bash
# Health check — should return the agent card JSON
curl -s http://steamdeck:7870/.well-known/agent.json | head -20

# Quick chat test
curl -s http://steamdeck:7870/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "/help"}' | python -m json.tool
```

You can also open the Gradio UI in a browser at `http://steamdeck:7870`.

::: tip Checking logs
If the server is not responding, check the journal:

```bash
journalctl --user -u protopen.service -f
```
:::

## Troubleshooting

| Issue | Fix |
|---|---|
| `pacman` fails with read-only errors | `sudo steamos-readonly disable` |
| `sudo` still asks for password | Verify file is named `zz-deck` with `0440` perms: `ls -la /etc/sudoers.d/zz-deck` |
| BlackArch strap fails GPG check | `sudo pacman-key --refresh-keys` |
| `git clone` fails "could not read Username" | Run `gh auth setup-git` to wire the credential helper |
| `pip install` fails on `sqlite-vec` | Install build deps: `sudo pacman -S gcc cmake` |
| SteamOS update broke everything | Re-run steps 2 and 3 (read-only disable, sudoers, pacman keyring) |
| Infisical fetch returns empty | Verify `INFISICAL_TOKEN` is set in the systemd override and run `systemctl --user daemon-reload` |
| Server not reachable over Tailscale | Verify `sudo tailscale up --ssh` and check `tailscale status` |
| tshark/dumpcap "permission denied" | `sudo usermod -aG wireshark deck` then restart the protopen service |
| `tool_use ids without tool_result` errors | Corrupted session DB — `rm -f /sandbox/knowledge/sessions.db*` and restart |

## Post-install: enable packet capture

tshark (Wireshark CLI) requires the `wireshark` group for raw packet capture:

```bash
sudo usermod -aG wireshark deck
```

Verify after re-login or service restart:

```bash
groups deck  # should include 'wireshark'
```

This enables the `blackarch tshark_capture` and `net_monitor traffic_baseline` tools for live LAN traffic analysis.

## What's next

With protoPen running on the Deck, continue to the [First Engagement](./first-engagement) tutorial to run a passive network scan using only the Deck's built-in hardware.
