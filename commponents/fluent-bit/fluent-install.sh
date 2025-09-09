#!/bin/bash
# =================================================================
# Fluent Bit Installation Script
# - Installs Fluent Bit (apt or yum/dnf), falling back to upstream script if needed
# - Renders and deploys config to forward Wazuh alerts to Graylog
# =================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# --------------- helpers ---------------
log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
die() { echo -e "[-] $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."; }

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE="$REPO_ROOT/.env"

LOCAL_CONF="$SCRIPT_DIR/fluent-bit.conf"
if [[ -f "$LOCAL_CONF" ]]; then
	FLUENT_CONFIG_SRC="$LOCAL_CONF"
else
	FLUENT_CONFIG_SRC=""
fi
FLUENT_CONFIG_DST="/etc/fluent-bit/fluent-bit.conf"

# --------------- 1) load env ---------------
log "Loading environment variables from $ENV_FILE"
[[ -f "$ENV_FILE" ]] || die ".env file not found at '$ENV_FILE'"
set -a; source "$ENV_FILE"; set +a

[[ -n "${GRAYLOG_SERVER_HOSTNAME:-}" ]] || die "GRAYLOG_SERVER_HOSTNAME not set in .env"

# --------------- 2) install fluent-bit ---------------
log "Installing Fluent Bit (using local install.sh)"
require_cmd sudo
require_cmd curl

INSTALLER="$SCRIPT_DIR/install.sh"
[[ -f "$INSTALLER" ]] || die "Installer not found at $INSTALLER"

# Ensure executable and run
sudo chmod +x "$INSTALLER" || true
sudo "$INSTALLER"

# Ensure envsubst exists for templating
if ! command -v envsubst >/dev/null 2>&1; then
	if command -v apt-get >/dev/null 2>&1; then
		sudo apt-get update -y && sudo apt-get install -y gettext-base
	elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
		PKG_MGR=$(command -v dnf || command -v yum)
		sudo "$PKG_MGR" -y install gettext
	else
		warn "envsubst not found and package manager unknown; templating may fail"
	fi
fi

# --------------- 3) configure fluent-bit ---------------
log "Configuring Fluent Bit"
[[ -n "$FLUENT_CONFIG_SRC" && -f "$FLUENT_CONFIG_SRC" ]] || die "Fluent Bit config template not found near $SCRIPT_DIR"

# Backup existing config if present
if [[ -f "$FLUENT_CONFIG_DST" ]]; then
	sudo cp -a "$FLUENT_CONFIG_DST" "${FLUENT_CONFIG_DST}.bak.$(date +%s)"
fi

require_cmd envsubst
export GRAYLOG_SERVER_HOSTNAME
envsubst '${GRAYLOG_SERVER_HOSTNAME}' < "$FLUENT_CONFIG_SRC" | sudo tee "$FLUENT_CONFIG_DST" >/dev/null
sudo chown root:root "$FLUENT_CONFIG_DST"
sudo chmod 644 "$FLUENT_CONFIG_DST"

log "Starting and enabling Fluent Bit service"
sudo systemctl daemon-reload
sudo systemctl enable --now fluent-bit || warn "Failed to start fluent-bit; check logs with: sudo journalctl -u fluent-bit -n 200 --no-pager"
if systemctl is-active --quiet fluent-bit; then
	log "Fluent Bit is active"
else
	warn "Fluent Bit is not active"
fi