#!/bin/bash

set -Eeuo pipefail
IFS=$'\n\t'

log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
die() { echo -e "[-] $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."; }

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
ENV_FILE="$REPO_ROOT/.env"

[[ -f "$ENV_FILE" ]] || die "$ENV_FILE file not found!"
set -a; source "$ENV_FILE"; set +a

# -------- Validate env --------
[[ -n "${WAZUH_MANAGER_IP:-}" ]] || die "WAZUH_MANAGER_IP not set in .env"
[[ -n "${WAZUH_MANAGER_HOSTNAME:-}" ]] || WAZUH_MANAGER_HOSTNAME="wazuh-manager"
[[ -n "${WAZUH_INDEXER_IP:-}" ]] || die "WAZUH_INDEXER_IP not set in .env"
[[ -n "${WAZUH_DASHBOARD_IP:-}" ]] || warn "WAZUH_DASHBOARD_IP not set; continuing"
[[ -n "${WAZUH_MANAGER_PASSWORD:-}" ]] || die "WAZUH_MANAGER_PASSWORD not set in .env"

TEMPLATE_FILE="$SCRIPT_DIR/ossec.conf"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

log "Installing Wazuh Manager..."
require_cmd sudo
require_cmd curl

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y debconf adduser procps gnupg apt-transport-https curl ca-certificates
    # Ensure envsubst is available
    if ! command -v envsubst >/dev/null 2>&1; then
        sudo apt-get install -y gettext-base
    fi
    # Repo and key
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | sudo gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        | sudo tee /etc/apt/sources.list.d/wazuh.list >/dev/null
    sudo apt-get update -y
    sudo apt-get install -y wazuh-manager=4.12.0-1
elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    PKG_MGR=$(command -v dnf || command -v yum)
    sudo "$PKG_MGR" -y install coreutils curl gnupg2 ca-certificates
    # Configure Wazuh repo
    sudo tee /etc/yum.repos.d/wazuh.repo >/dev/null <<'REPO'
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
REPO
    sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    sudo "$PKG_MGR" -y makecache
    # Ensure envsubst is available
    if ! command -v envsubst >/dev/null 2>&1; then
        sudo "$PKG_MGR" -y install gettext
    fi
    sudo "$PKG_MGR" -y install wazuh-manager-4.12.0-1
else
    die "Neither apt-get, yum, nor dnf found!"
fi

log "Configuring Wazuh Manager..."
require_cmd envsubst

# Backup existing configuration
if [[ -f "$OSSEC_CONF" ]]; then
    sudo cp -a "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%s)"
fi

# Render ossec.conf from template
export WAZUH_INDEXER_IP
if [[ ! -f "$TEMPLATE_FILE" ]]; then
    die "Template not found: $TEMPLATE_FILE"
fi
envsubst '${WAZUH_INDEXER_IP}' < "$TEMPLATE_FILE" | sudo tee "$OSSEC_CONF" >/dev/null
sudo chown root:wazuh "$OSSEC_CONF"
sudo chmod 640 "$OSSEC_CONF"

# Set authd password securely
AUTHD_PASS_FILE="/var/ossec/etc/authd.pass"
printf "%s" "${WAZUH_MANAGER_PASSWORD}" | sudo tee "$AUTHD_PASS_FILE" >/dev/null
sudo chown root:wazuh "$AUTHD_PASS_FILE"
sudo chmod 640 "$AUTHD_PASS_FILE"

# Deploy shared agent configurations if present
DEST_SHARED_DIR="/var/ossec/etc/shared"
sudo mkdir -p "$DEST_SHARED_DIR"
if [[ -d "$SCRIPT_DIR/agent_configs/Linux" ]]; then
    sudo cp -r "$SCRIPT_DIR/agent_configs/Linux" "$DEST_SHARED_DIR/"
fi
if [[ -d "$SCRIPT_DIR/agent_configs/Windows" ]]; then
    sudo cp -r "$SCRIPT_DIR/agent_configs/Windows" "$DEST_SHARED_DIR/"
fi

log "Starting Wazuh Manager service..."
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-manager
if ! sudo systemctl is-active --quiet wazuh-manager; then
    sudo journalctl -u wazuh-manager -n 100 --no-pager || true
    die "Wazuh Manager service failed to start"
fi
log "Wazuh Manager is active"