#!/usr/bin/env bash
# =================================================================
# SOC-SIEM Orchestrated Installer
# Runs component installers in a safe order using the repo's scripts.
# =================================================================
set -Eeuo pipefail
IFS=$'\n\t'

log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
err() { echo -e "[-] $*" >&2; }
die() { err "$*"; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found"; }

REPO_ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
ENV_FILE="$REPO_ROOT/.env"

# Load env
log "Loading environment from $ENV_FILE"
[[ -f "$ENV_FILE" ]] || die ".env not found at $ENV_FILE"
set -a; source "$ENV_FILE"; set +a

# Paths
CFG_DIR="$REPO_ROOT/commponents/config"
INDEXER_DIR="$REPO_ROOT/commponents/wauzh/wazuh-indexer"
DASHBOARD_DIR="$REPO_ROOT/commponents/wauzh/wazuh-dashboard"
MANAGER_DIR="$REPO_ROOT/commponents/wauzh/wazuh-manager"
GRAYLOG_DIR="$REPO_ROOT/commponents/graylog"
FLUENT_DIR="$REPO_ROOT/commponents/fluent-bit"
GRAFANA_DIR="$REPO_ROOT/commponents/grafana"

# Step helpers
run_step() {
  local name="$1"; shift
  log "=== $name ==="
  "$@"
}

require_cmd sudo

# 1) Certificates (optional if already generated)
if [[ -f "$CFG_DIR/generate_certs.sh" ]]; then
  read -r -p "Generate Wazuh certificates? (y/N) " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    run_step "Generate certificates" bash "$CFG_DIR/generate_certs.sh"
  else
    log "Skipping certificate generation"
  fi
else
  warn "generate_certs.sh not found; ensure certs exist in commponents/config/wazuh-certificates.tar"
fi

# 2) Wazuh Indexer
[[ -x "$INDEXER_DIR/indexer-install.sh" ]] || die "Indexer installer not found"
run_step "Install Wazuh Indexer" bash "$INDEXER_DIR/indexer-install.sh"

# 3) Wazuh Dashboard
[[ -x "$DASHBOARD_DIR/dashborad-install.sh" ]] || die "Dashboard installer not found"
run_step "Install Wazuh Dashboard" bash "$DASHBOARD_DIR/dashborad-install.sh"

# 4) Wazuh Manager
[[ -x "$MANAGER_DIR/manager-install.sh" ]] || die "Manager installer not found"
run_step "Install Wazuh Manager" bash "$MANAGER_DIR/manager-install.sh"

# 5) Graylog
[[ -x "$GRAYLOG_DIR/graylog-install.sh" ]] || die "Graylog installer not found"
run_step "Install Graylog" bash "$GRAYLOG_DIR/graylog-install.sh"

# 6) Fluent Bit (forward Wazuh alerts)
[[ -x "$FLUENT_DIR/fluent-install.sh" ]] || die "Fluent Bit installer not found"
run_step "Install Fluent Bit" bash "$FLUENT_DIR/fluent-install.sh"

# 7) Grafana
[[ -x "$GRAFANA_DIR/grafana-install.sh" ]] || die "Grafana installer not found"
run_step "Install Grafana" bash "$GRAFANA_DIR/grafana-install.sh"

log "All steps completed. Review each service status and logs if needed."
