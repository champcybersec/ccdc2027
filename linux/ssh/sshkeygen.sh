
#!/usr/bin/env bash
set -euo pipefail

# CCDC SSH Key-Only Hardening
# Run as root: sudo bash secure-ssh.sh <username>

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run this script as root."
    exit 1
fi

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <username>"
    exit 1
fi

USER_NAME="$1"

if ! id "$USER_NAME" &>/dev/null; then
    echo "ERROR: User '$USER_NAME' does not exist."
    exit 1
fi

USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)
USER_GROUP=$(id -gn "$USER_NAME")

SSH_DIR="$USER_HOME/.ssh"
KEY_DIR="/root/ccdc-ssh-keys"
KEY_FILE="$KEY_DIR/${HOSTNAME}-${USER_NAME}-ed25519"
CONFIG_FILE="/etc/ssh/sshd_config.d/99-ccdc-keyonly.conf"

mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

if [[ -e "$KEY_FILE" ]]; then
    echo "ERROR: Key file already exists: $KEY_FILE"
    exit 1
fi

echo "[+] Generating Ed25519 SSH key pair..."
ssh-keygen -t ed25519 \
    -f "$KEY_FILE" \
    -N "" \
    -C "ccdc-${HOSTNAME}-${USER_NAME}"

chmod 600 "$KEY_FILE"
chmod 644 "$KEY_FILE.pub"

echo "[+] Installing SSH public key..."

install -d -m 700 -o "$USER_NAME" -g "$USER_GROUP" "$SSH_DIR"

touch "$SSH_DIR/authorized_keys"
chown "$USER_NAME:$USER_GROUP" "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"

PUBLIC_KEY=$(cat "$KEY_FILE.pub")

if ! grep -qxF "$PUBLIC_KEY" "$SSH_DIR/authorized_keys"; then
    echo "$PUBLIC_KEY" >> "$SSH_DIR/authorized_keys"
fi

# Restore SELinux labels when supported
if command -v restorecon &>/dev/null; then
    restorecon -RF "$SSH_DIR"
fi

echo
echo "=================================================="
echo " SSH KEY GENERATED"
echo "=================================================="
echo "Hostname:    $HOSTNAME"
echo "Username:    $USER_NAME"
echo "Private key: $KEY_FILE"
echo "Public key:  $KEY_FILE.pub"
echo
echo "Test SSH key authentication before enabling key-only mode."
echo
echo "Example:"
echo "ssh -i ${HOSTNAME}-${USER_NAME}-ed25519 ${USER_NAME}@SERVER_IP"
echo

read -r -p "Have you successfully tested key authentication? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo "[!] Password authentication has NOT been disabled."
    exit 0
fi

echo "[+] Configuring SSH key-only authentication..."

# Backup existing configuration
BACKUP="/etc/ssh/sshd_config.ccdc.bak.$(date +%Y%m%d%H%M%S)"
cp -a /etc/ssh/sshd_config "$BACKUP"

# Set effective options in main config, accounting for
# existing directives and Match blocks.
python3 - <<'PY'
from pathlib import Path

path = Path("/etc/ssh/sshd_config")
lines = path.read_text().splitlines()

settings = {
    "PubkeyAuthentication": "yes",
    "PasswordAuthentication": "no",
    "KbdInteractiveAuthentication": "no",
    "ChallengeResponseAuthentication": "no",
    "PermitRootLogin": "no",
    "AuthenticationMethods": "publickey",
}

# Remove existing global instances of the settings.
# Preserve Match blocks rather than modifying them blindly.
result = []
in_match = False

for line in lines:
    stripped = line.strip()
    if stripped.lower().startswith("match "):
        in_match = True

    if not in_match:
        directive = stripped.split(maxsplit=1)[0].lower() if stripped else ""
        if directive in {key.lower() for key in settings}:
            continue

    result.append(line)

# Put policy first, ahead of Include directives.
policy = [f"{key} {value}" for key, value in settings.items()]
path.write_text("\n".join(policy + result) + "\n")
PY

echo "[+] Validating SSH configuration..."

if ! sshd -t; then
    echo "[!] Invalid SSH configuration."
    cp -a "$BACKUP" /etc/ssh/sshd_config
    echo "[!] Restored original configuration."
    exit 1
fi

echo "[+] Reloading SSH service..."

if systemctl is-active --quiet sshd; then
    systemctl reload sshd
elif systemctl is-active --quiet ssh; then
    systemctl reload ssh
else
    echo "[!] SSH service not detected. Reload manually."
    exit 1
fi

echo
echo "=================================================="
echo " SSH HARDENING COMPLETE"
echo "=================================================="
echo "Password authentication: DISABLED"
echo "Keyboard-interactive:    DISABLED"
echo "Public key auth:         ENABLED"
echo "Root SSH login:          DISABLED"
echo
echo "Original config backup: $BACKUP"
echo "Private key: $KEY_FILE"
echo
echo "Keep your current SSH session open."
echo "Test a NEW SSH connection before disconnecting."
