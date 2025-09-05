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
CONFIG_TAR="$SCRIPT_DIR/../../config/wazuh-certificates.tar"

# --- Load environment variables ---
if [[ -f "$ENV_FILE" ]]; then
    log "Loading environment variables from $ENV_FILE"
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
else
    die "$ENV_FILE file not found!"
fi

# Validate required variables
[[ -n "${WAZUH_INDEXER_HOSTNAME:-}" ]] || die "WAZUH_INDEXER_HOSTNAME not set in .env"
[[ -n "${WAZUH_INDEXER_IP:-}" ]] || die "WAZUH_INDEXER_IP not set in .env"
[[ -n "${WAZUH_INDEXER_PASSWORD:-}" ]] || die "WAZUH_INDEXER_PASSWORD not set in .env"
[[ -n "${WAZUH_KIBANASERVER_PASSWORD:-}" ]] || die "WAZUH_KIBANASERVER_PASSWORD not set in .env"
[[ -n "${GRAYLOG_PASSWORD:-}" ]] || die "GRAYLOG_PASSWORD not set in .env"

# --- Install dependencies and Wazuh Indexer ---
log "Installing Wazuh Indexer..."
require_cmd sudo
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y debconf adduser procps gnupg apt-transport-https curl pwgen
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        sudo gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
        sudo tee /etc/apt/sources.list.d/wazuh.list >/dev/null
    sudo apt-get update -y
    sudo apt-get install -y wazuh-indexer=4.12.0-1
elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y coreutils curl gnupg2 pwgen
    sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    sudo yum install -y wazuh-indexer-4.12.0-1
else
    die "Neither apt-get nor yum found!"
fi

# --- Certificates setup ---
log "Setting up certificates..."
NODE_NAME="${WAZUH_INDEXER_HOSTNAME}"
sudo mkdir -p /etc/wazuh-indexer/certs
[[ -f "$CONFIG_TAR" ]] || die "Certificates archive not found at $CONFIG_TAR"
sudo tar -xf "$CONFIG_TAR" -C /etc/wazuh-indexer/certs/ \
    "./${NODE_NAME}.pem" \
    "./${NODE_NAME}-key.pem" \
    ./admin.pem \
    ./admin-key.pem \
    ./root-ca.pem

sudo chmod 500 /etc/wazuh-indexer/certs
sudo chmod 400 /etc/wazuh-indexer/certs/*
sudo chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# --- Deploy opensearch.yml ---
log "Deploying opensearch.yml..."
require_cmd envsubst
TEMPLATE_FILE="$SCRIPT_DIR/opensearch.yml"
TARGET_CONFIG="/etc/wazuh-indexer/opensearch.yml"
envsubst '${WAZUH_INDEXER_HOSTNAME}' < "$TEMPLATE_FILE" | sudo tee "$TARGET_CONFIG" >/dev/null
sudo chown wazuh-indexer:wazuh-indexer "$TARGET_CONFIG"
sudo chmod 640 "$TARGET_CONFIG"

# --- Ensure LimitMEMLOCK is set ---
log "Ensuring LimitMEMLOCK=infinity in systemd service..."
SERVICE_FILE="/usr/lib/systemd/system/wazuh-indexer.service"
[[ -f "$SERVICE_FILE" ]] || SERVICE_FILE="/lib/systemd/system/wazuh-indexer.service"
if [[ -f "$SERVICE_FILE" ]] && ! grep -q "^LimitMEMLOCK=infinity" "$SERVICE_FILE"; then
    sudo sed -i '/^\[Service\]/a LimitMEMLOCK=infinity' "$SERVICE_FILE"
fi

# --- Enable and start service ---
log "Enabling and starting Wazuh Indexer..."
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-indexer

# --- Initialize security ---
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh

# --- Test connectivity ---
log "Testing Wazuh Indexer..."
until curl -sk -u admin:admin "https://${WAZUH_INDEXER_IP}:9200" >/dev/null; do
    echo "    Wazuh Indexer is not ready yet. Retrying in 5 seconds..."
    sleep 5
done
log "Wazuh Indexer is up!"

SEC_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools"
HASH_SH="$SEC_TOOL/hash.sh"
SECADMIN_SH="$SEC_TOOL/securityadmin.sh"
require_cmd "$HASH_SH" || true
require_cmd "$SECADMIN_SH" || true

ADMIN_HASH=$("$HASH_SH" -p "${WAZUH_INDEXER_PASSWORD}" | tail -n 1)
KIBANA_HASH=$("$HASH_SH" -p "${WAZUH_KIBANASERVER_PASSWORD}" | tail -n 1)
GRAYLOG_HASH=$("$HASH_SH" -p "${GRAYLOG_PASSWORD}" | tail -n 1)

INT_USERS_TMPL="$SCRIPT_DIR/internal_users.yml"
INT_USERS_GEN="/tmp/internal_users_update.yml"
envsubst '${ADMIN_HASH} ${KIBANA_HASH} ${GRAYLOG_HASH}' < "$INT_USERS_TMPL" | sudo tee "$INT_USERS_GEN" >/dev/null

sudo JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    "$SECADMIN_SH" \
    -f "$INT_USERS_GEN" \
    -t internalusers \
    -icl -nhnv \
    -h "${WAZUH_INDEXER_IP}" \
    -cacert /etc/wazuh-indexer/certs/root-ca.pem \
    -cert /etc/wazuh-indexer/certs/admin.pem \
    -key /etc/wazuh-indexer/certs/admin-key.pem

sudo rm -f "$INT_USERS_GEN"

log "Wazuh Indexer configured!"
curl -sk -u admin:"$WAZUH_INDEXER_PASSWORD" "https://${WAZUH_INDEXER_IP}:9200" >/dev/null || warn "Connectivity test with updated password failed"