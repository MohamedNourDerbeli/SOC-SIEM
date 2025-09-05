#!/bin/bash

set -Eeuo pipefail
IFS=$'\n\t'

log() { echo -e "[+] $*"; }
die() { echo -e "[-] $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."; }

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
ENV_FILE="$REPO_ROOT/.env"
CONFIG_TAR="$SCRIPT_DIR/../../config/wazuh-certificates.tar"

[[ -f "$ENV_FILE" ]] || die "$ENV_FILE file not found!"
set -a; source "$ENV_FILE"; set +a

NODE_NAME="${WAZUH_DASHBOARD_HOSTNAME}"
[[ -n "${WAZUH_INDEXER_IP:-}" ]] || die "WAZUH_INDEXER_IP not set in .env"
[[ -n "${WAZUH_DASHBOARD_IP:-}" ]] || WAZUH_DASHBOARD_IP=127.0.0.1
[[ -n "${WAZUH_INDEXER_PASSWORD:-}" ]] || die "WAZUH_INDEXER_PASSWORD not set in .env"
[[ -n "${WAZUH_KIBANASERVER_PASSWORD:-}" ]] || die "WAZUH_KIBANASERVER_PASSWORD not set in .env"

log "Installing Wazuh Dashboard..."
require_cmd sudo
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y debhelper tar curl libcap2-bin
    sudo apt-get install -y wazuh-dashboard=4.12.0-1
elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y tar curl libcap
    sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    sudo yum install -y wazuh-dashboard-4.12.0-1
else
    die "Neither apt-get nor yum found!"
fi

log "Setting up certificates..."
sudo mkdir -p /etc/wazuh-dashboard/certs
[[ -f "$CONFIG_TAR" ]] || die "Certificates archive not found at $CONFIG_TAR"
sudo tar -xf "$CONFIG_TAR" -C /etc/wazuh-dashboard/certs/ \
    "./${NODE_NAME}.pem" \
    "./${NODE_NAME}-key.pem" \
    ./root-ca.pem
sudo chmod 500 /etc/wazuh-dashboard/certs
sudo chmod 400 /etc/wazuh-dashboard/certs/*
sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

log "Deploying opensearch_dashboards.yml"
require_cmd envsubst
TEMPLATE_FILE="$SCRIPT_DIR/opensearch_dashboards.yml"
DASHBOARD_CONFIG_FILE="/etc/wazuh-dashboard/opensearch_dashboards.yml"
envsubst '${WAZUH_INDEXER_IP} ${NODE_NAME}' < "$TEMPLATE_FILE" | sudo tee "$DASHBOARD_CONFIG_FILE" >/dev/null

echo "${WAZUH_KIBANASERVER_PASSWORD}" | sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password

log "Enabling and starting Wazuh Dashboard..."
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-dashboard

echo "[+] Wazuh Dashboard installation and configuration completed."
echo "    - Access the dashboard at: https://${WAZUH_DASHBOARD_IP}:443"
echo "    - Login: admin"
echo "    - Password: ${WAZUH_INDEXER_PASSWORD}"