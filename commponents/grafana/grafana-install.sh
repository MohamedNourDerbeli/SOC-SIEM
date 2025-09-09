#!/bin/bash
# =================================================================
# Grafana Installation Script
# - Installs Grafana (apt or yum/dnf)
# - Renders grafana.ini with env vars and configures TLS if certs exist
# - Optionally sets admin password
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
CONFIG_TAR="$SCRIPT_DIR/../../config/wazuh-certificates.tar"
TEMPLATE_INI="$SCRIPT_DIR/grafana.ini"
DEST_INI="/etc/grafana/grafana.ini"

# --------------- 1) load env ---------------
log "Loading environment variables from $ENV_FILE"
[[ -f "$ENV_FILE" ]] || die ".env file not found at '$ENV_FILE'"
set -a; source "$ENV_FILE"; set +a

[[ -n "${GRAFANA_DASHBOARD_HOSTNAME:-}" ]] || die "GRAFANA_DASHBOARD_HOSTNAME not set in .env"
NODE_NAME="${NODE_NAME:-$GRAFANA_DASHBOARD_HOSTNAME}"

# --------------- 2) install grafana ---------------
log "Installing Grafana"
require_cmd sudo
require_cmd curl

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y apt-transport-https software-properties-common wget gpg ca-certificates
    sudo mkdir -p /etc/apt/keyrings/
    curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg >/dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
        | sudo tee /etc/apt/sources.list.d/grafana.list >/dev/null
    sudo apt-get update -y
    sudo apt-get install -y grafana
    if ! command -v envsubst >/dev/null 2>&1; then sudo apt-get install -y gettext-base; fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PKG_MGR=$(command -v dnf || command -v yum)
    sudo "$PKG_MGR" -y install curl ca-certificates gnupg2 || true
    sudo tee /etc/yum.repos.d/grafana.repo >/dev/null <<'REPO'
[grafana]
name=Grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
REPO
    sudo rpm --import https://rpm.grafana.com/gpg.key || true
    sudo "$PKG_MGR" -y makecache || true
    sudo "$PKG_MGR" -y install grafana
    if ! command -v envsubst >/dev/null 2>&1; then sudo "$PKG_MGR" -y install gettext; fi
else
    die "Unsupported package manager; please install Grafana manually"
fi

# --------------- 3) certificates (required for HTTPS) ---------------
CERT_FILE="/etc/ssl/certs/${NODE_NAME}.pem"
KEY_FILE="/etc/ssl/private/${NODE_NAME}.key"
sudo mkdir -p /etc/ssl/certs /etc/ssl/private

if [[ -f "$CONFIG_TAR" ]]; then
    # Check if certs for NODE_NAME exist inside the tar (entries are top-level filenames)
    if tar -tf "$CONFIG_TAR" | grep -qx "${NODE_NAME}\.pem" && \
         tar -tf "$CONFIG_TAR" | grep -qx "${NODE_NAME}-key\.pem"; then
        log "Extracting TLS certs for $NODE_NAME from bundle"
        sudo tar -xf "$CONFIG_TAR" -C /etc/ssl/certs "${NODE_NAME}.pem"
        sudo tar -xf "$CONFIG_TAR" -C /etc/ssl/private "${NODE_NAME}-key.pem"
        sudo chmod 644 "$CERT_FILE" || true
        sudo chmod 600 "$KEY_FILE" || true
    else
        die "No certs for ${NODE_NAME} found in bundle: $CONFIG_TAR"
    fi
else
    die "Certificates archive not found at $CONFIG_TAR"
fi

# Validate that cert and key files are present after extraction
[[ -s "$CERT_FILE" ]] || die "Certificate not found after extraction: $CERT_FILE"
[[ -s "$KEY_FILE" ]] || die "Private key not found after extraction: $KEY_FILE"

# --------------- 4) render grafana.ini ---------------
log "Configuring Grafana"
[[ -f "$TEMPLATE_INI" ]] || die "Template not found: $TEMPLATE_INI"

export GRAFANA_DASHBOARD_HOSTNAME NODE_NAME
TMP_INI="/tmp/grafana.ini.rendered"
require_cmd envsubst
envsubst '${GRAFANA_DASHBOARD_HOSTNAME} ${NODE_NAME}' < "$TEMPLATE_INI" > "$TMP_INI"


sudo mkdir -p /etc/grafana
sudo cp "$TMP_INI" "$DEST_INI"
sudo chown root:root "$DEST_INI"
sudo chmod 640 "$DEST_INI"
rm -f "$TMP_INI"

# --------------- 5) Provision datasource and dashboard ---------------
log "Provisioning Grafana datasource and dashboard"
DATASOURCES_DIR="/etc/grafana/provisioning/datasources"
DASHBOARDS_DIR="/etc/grafana/provisioning/dashboards"
DASH_JSON_DIR="/var/lib/grafana/dashboards"
sudo mkdir -p "$DATASOURCES_DIR" "$DASHBOARDS_DIR" "$DASH_JSON_DIR"

# Datasource provisioning (render with env then copy)
DS_TMPL="$SCRIPT_DIR/grafana_datasource.yml"
if [[ -f "$DS_TMPL" ]]; then
    require_cmd envsubst
    export WAZUH_INDEXER_IP GRAFANA_INDEXER_PASSWORD GRAYLOG_SERVER_HOSTNAME
    TMP_DS=$(mktemp)
    envsubst '${WAZUH_INDEXER_IP} ${GRAFANA_INDEXER_PASSWORD} ${GRAYLOG_SERVER_HOSTNAME}' < "$DS_TMPL" > "$TMP_DS"
    sudo cp "$TMP_DS" "$DATASOURCES_DIR/wazuh.yml"
    rm -f "$TMP_DS"
else
    warn "Datasource file not found: $DS_TMPL"
fi

# Dashboards provisioning provider
sudo tee "$DASHBOARDS_DIR/wazuh.yml" >/dev/null <<'YAML'
apiVersion: 1
providers:
  - name: Wazuh
    orgId: 1
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
YAML

# Place dashboard JSON (will patch datasource UID after Grafana starts)
DASH_SRC="$SCRIPT_DIR/grafana_dashboards.yml"
DASH_DST="$DASH_JSON_DIR/wazuh_sysmon_network.json"
if [[ -f "$DASH_SRC" ]]; then
    sudo cp "$DASH_SRC" "$DASH_DST"
else
    warn "Dashboard JSON not found: $DASH_SRC"
fi

# --------------- 6) Create Wazuh Indexer role and user for Grafana ---------------
log "Creating Wazuh Indexer role and user for Grafana"
[[ -n "${WAZUH_INDEXER_IP:-}" ]] || die "WAZUH_INDEXER_IP not set in .env"
require_cmd openssl

SECURITY_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools"
HASH_SH="$SECURITY_TOOL/hash.sh"
SECADMIN_SH="$SECURITY_TOOL/securityadmin.sh"
[[ -x "$HASH_SH" ]] || die "hash.sh not found at $HASH_SH. Is Wazuh Indexer installed on this host?"
[[ -x "$SECADMIN_SH" ]] || die "securityadmin.sh not found at $SECADMIN_SH. Is Wazuh Indexer installed on this host?"

# Ensure required certs to connect to Indexer
CACERT="/etc/wazuh-indexer/certs/root-ca.pem"
ADMIN_CERT="/etc/wazuh-indexer/certs/admin.pem"
ADMIN_KEY="/etc/wazuh-indexer/certs/admin-key.pem"
[[ -f "$CACERT" && -f "$ADMIN_CERT" && -f "$ADMIN_KEY" ]] || die "Missing Indexer certs at /etc/wazuh-indexer/certs"

# Password for the grafna user (env or generated)
if [[ -z "${GRAFANA_INDEXER_PASSWORD:-}" ]]; then
    GRAFANA_INDEXER_PASSWORD=$(openssl rand -base64 18)
    log "Generated GRAFANA_INDEXER_PASSWORD (save this): $GRAFANA_INDEXER_PASSWORD"
fi

# Hash the password and render internal user from template
export GRAFANA_INDEXER_HASH
GRAFANA_INDEXER_HASH=$("$HASH_SH" -p "${GRAFANA_INDEXER_PASSWORD}" | tail -n 1)
TEMPLATE_USER="$SCRIPT_DIR/grafana_user.yml"
[[ -f "$TEMPLATE_USER" ]] || die "Template not found: $TEMPLATE_USER"
TMP_USER=$(mktemp)
envsubst '${GRAFANA_INDEXER_HASH}' < "$TEMPLATE_USER" > "$TMP_USER"

# Use role and mapping templates from repo
ROLE_TMPL="$SCRIPT_DIR/grafana_role.yml"
MAP_TMPL="$SCRIPT_DIR/grafana_rolesmapping.yml"
[[ -f "$ROLE_TMPL" ]] || die "Role template not found: $ROLE_TMPL"
[[ -f "$MAP_TMPL" ]] || die "Roles mapping template not found: $MAP_TMPL"
TMP_ROLE=$(mktemp)
TMP_MAP=$(mktemp)
cp "$ROLE_TMPL" "$TMP_ROLE"
cp "$MAP_TMPL" "$TMP_MAP"

# Apply role, user, and mapping
sudo JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    "$SECADMIN_SH" -f "$TMP_ROLE" -t roles -icl -nhnv -h "$WAZUH_INDEXER_IP" \
    -cacert "$CACERT" -cert "$ADMIN_CERT" -key "$ADMIN_KEY"

sudo JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    "$SECADMIN_SH" -f "$TMP_USER" -t internalusers -icl -nhnv -h "$WAZUH_INDEXER_IP" \
    -cacert "$CACERT" -cert "$ADMIN_CERT" -key "$ADMIN_KEY"

sudo JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    "$SECADMIN_SH" -f "$TMP_MAP" -t rolesmapping -icl -nhnv -h "$WAZUH_INDEXER_IP" \
    -cacert "$CACERT" -cert "$ADMIN_CERT" -key "$ADMIN_KEY"

rm -f "$TMP_ROLE" "$TMP_USER" "$TMP_MAP"

# --------------- 7) set admin password---------------
if [[ -n "${GRAFANA_ADMIN_PASSWORD:-}" ]]; then
    if command -v grafana-cli >/dev/null 2>&1; then
        log "Setting Grafana admin password"
        sudo grafana-cli admin reset-admin-password "$GRAFANA_ADMIN_PASSWORD" || warn "Failed to set admin password"
    else
        warn "grafana-cli not found; skipping admin password setup"
    fi
fi

# --------------- 8) start service ---------------
log "Enabling and starting grafana-server"
sudo systemctl daemon-reload
sudo systemctl enable --now grafana-server || warn "Failed to start grafana-server; check logs with: sudo journalctl -u grafana-server -n 200 --no-pager"
if systemctl is-active --quiet grafana-server; then
    log "Grafana is active: https://${GRAFANA_DASHBOARD_HOSTNAME}:3000"
else
    warn "Grafana service not active"
fi


