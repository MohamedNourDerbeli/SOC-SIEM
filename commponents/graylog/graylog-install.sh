#!/bin/bash

# =================================================================
# Graylog & Dependencies Installation Script (Ubuntu 22.04)
# - Installs MongoDB and Graylog Server
# - Imports Wazuh Indexer root CA into Graylog Java truststore
# - Creates Graylog internal user in OpenSearch (via Wazuh Indexer tools)
# - Renders Graylog server.conf from template with env vars
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
CONFIG_DIR="$SCRIPT_DIR/../config"

TMP_INTERNAL_USERS="/tmp/graylog_users_update.yml"

cleanup() {
  rm -f "$TMP_INTERNAL_USERS" || true
}
trap cleanup EXIT

# --------------- 1) load env ---------------
log "Loading environment variables from $ENV_FILE"
[[ -f "$ENV_FILE" ]] || die ".env file not found at '$ENV_FILE'"
set -a
source "$ENV_FILE"
set +a

# Basic required vars
[[ -n "${PASSWORD_SECRET:-}" ]] || die "PASSWORD_SECRET not set in .env"
[[ -n "${GRAYLOG_PASSWORD:-}" ]] || die "GRAYLOG_PASSWORD not set in .env"
[[ -n "${WAZUH_INDEXER_IP:-}" ]] || die "WAZUH_INDEXER_IP not set in .env"

# --------------- 2) prerequisites ---------------
log "Installing prerequisite packages (gnupg, curl, wget, pwgen, openjdk)"
require_cmd sudo
sudo apt-get update -y
sudo apt-get install -y gnupg curl wget pwgen openjdk-11-jre-headless

# --------------- 3) MongoDB 7.0 ---------------
log "Installing MongoDB 7.0"
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc \
  | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
  | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list >/dev/null

sudo apt-get update -y
sudo apt-get install -y mongodb-org
sudo systemctl daemon-reload
sudo systemctl enable --now mongod
sudo systemctl is-active --quiet mongod || die "MongoDB service failed to start"
log "MongoDB is active"

# --------------- 4) Graylog 6.3 ---------------
log "Installing Graylog Server"
wget -q https://packages.graylog2.org/repo/packages/graylog-6.3-repository_latest.deb -O /tmp/graylog-6.3-repo.deb
sudo dpkg -i /tmp/graylog-6.3-repo.deb
sudo apt-get update -y
sudo apt-get install -y graylog-server=6.3.2-1

# --------------- 5) Trust Wazuh root CA ---------------
log "Preparing Graylog truststore and importing Wazuh root CA"
sudo mkdir -p /etc/graylog/server/certs

# Locate Java cacerts; prefer OpenJDK 11 default path, fallback to system path if missing
JAVA_CACERTS_SRC="/usr/lib/jvm/java-11-openjdk-amd64/lib/security/cacerts"
if [[ ! -f "$JAVA_CACERTS_SRC" ]]; then
  JAVA_CACERTS_SRC="/etc/ssl/certs/java/cacerts"
fi
[[ -f "$JAVA_CACERTS_SRC" ]] || die "Java cacerts not found. Ensure OpenJDK 11 is installed."

sudo cp -a "$JAVA_CACERTS_SRC" /etc/graylog/server/certs/cacerts

# Extract root-ca.pem from generated bundle
CERT_TAR="$CONFIG_DIR/wazuh-certificates.tar"
[[ -f "$CERT_TAR" ]] || die "Certificate bundle not found at '$CERT_TAR'"
sudo tar -xf "$CERT_TAR" -C /etc/graylog/server/certs/ ./root-ca.pem

require_cmd keytool
sudo keytool -importcert \
  -keystore /etc/graylog/server/certs/cacerts \
  -storepass changeit \
  -alias root_ca \
  -file /etc/graylog/server/certs/root-ca.pem \
  -noprompt

sudo chown -R graylog:graylog /etc/graylog/server/certs
sudo chmod 640 /etc/graylog/server/certs/cacerts

# --------------- 6) Create internal OS user for Graylog ---------------
log "Creating OpenSearch internal user for Graylog"
require_cmd envsubst

# Generate secrets and hashes
export ROOT_PASSWORD_SHA2
ROOT_PASSWORD_SHA2=$(echo -n "${GRAYLOG_PASSWORD}" | sha256sum | awk '{print $1}')

export GRAYLOG_INDEXER_PASSWORD
GRAYLOG_INDEXER_PASSWORD=$(pwgen -N 1 -s 15)

SECURITY_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools"
HASH_SH="$SECURITY_TOOL/hash.sh"
SECADMIN_SH="$SECURITY_TOOL/securityadmin.sh"
[[ -x "$HASH_SH" ]] || die "hash.sh not found at $HASH_SH. Is Wazuh Indexer installed on this host?"
[[ -x "$SECADMIN_SH" ]] || die "securityadmin.sh not found at $SECADMIN_SH. Is Wazuh Indexer installed on this host?"

# Template expects ${GRAYLOG_HASH}
export GRAYLOG_HASH
GRAYLOG_HASH=$("$HASH_SH" -p "${GRAYLOG_INDEXER_PASSWORD}" | tail -n 1)

TEMPLATE_FILE="$SCRIPT_DIR/graylog_user.yml"
[[ -f "$TEMPLATE_FILE" ]] || die "Template not found: $TEMPLATE_FILE"

envsubst '${GRAYLOG_HASH}' < "$TEMPLATE_FILE" | sudo tee "$TMP_INTERNAL_USERS" >/dev/null

sudo JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  "$SECADMIN_SH" \
  -f "$TMP_INTERNAL_USERS" \
  -t internalusers \
  -icl -nhnv \
  -h "${WAZUH_INDEXER_IP}" \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem

# --------------- 7) Render Graylog config ---------------
log "Rendering Graylog server.conf from template"
export PASSWORD_SECRET
export WAZUH_INDEXER_IP
export ROOT_PASSWORD_SHA2
export GRAYLOG_INDEXER_PASSWORD

GRAYLOG_CONFIG_TMPL="$SCRIPT_DIR/server.conf"
[[ -f "$GRAYLOG_CONFIG_TMPL" ]] || die "Graylog config template not found: $GRAYLOG_CONFIG_TMPL"
envsubst '${PASSWORD_SECRET} ${ROOT_PASSWORD_SHA2} ${GRAYLOG_INDEXER_PASSWORD} ${WAZUH_INDEXER_IP}' \
  < "$GRAYLOG_CONFIG_TMPL" | sudo tee /etc/graylog/server/server.conf >/dev/null

# --------------- 8) Override graylog-server binary (if provided) ---------------
CUSTOM_BIN="$SCRIPT_DIR/graylog-server"
if [[ -f "$CUSTOM_BIN" ]]; then
  log "Installing custom graylog-server binary"
  sudo cp "$CUSTOM_BIN" /usr/share/graylog-server/bin/graylog-server
  sudo chmod +x /usr/share/graylog-server/bin/graylog-server
  sudo chown graylog:graylog /usr/share/graylog-server/bin/graylog-server
else
  warn "Custom graylog-server binary not found at $CUSTOM_BIN; skipping override"
fi


# --------------- 9) Start Graylog ---------------
log "Enabling and starting graylog-server"
sudo systemctl daemon-reload
sudo systemctl enable --now graylog-server || warn "graylog-server failed to start; check logs with: sudo journalctl -u graylog-server -n 200 --no-pager"

echo
echo "=============================================================="
echo " Graylog and MongoDB installation finished"
echo " - Graylog URL: http://${GRAYLOG_SERVER_IP}:9000"
echo " - Index backend: https://${WAZUH_INDEXER_IP}:9200 (auth: graylog/${GRAYLOG_INDEXER_PASSWORD})"
echo " - Root user: admin (password set via ROOT_PASSWORD_SHA2 from .env)"
echo "=============================================================="


# --------------- 10) Install Graylog content packs (optional) ---------------
install_graylog_content_packs() {
  # Ensure needed tools
  require_cmd curl
  if ! command -v jq >/dev/null 2>&1; then
    warn "jq not found; installing jq"
    sudo apt-get update -y && sudo apt-get install -y jq || die "Failed to install jq"
  fi

  # Required vars
  [[ -n "${GRAYLOG_SERVER_IP:-}" ]] || die "GRAYLOG_SERVER_IP not set in .env"
  [[ -n "${GRAYLOG_PASSWORD:-}" ]] || die "GRAYLOG_PASSWORD not set in .env"

  local API_URL="http://${GRAYLOG_SERVER_IP}:9000/api"
  local ADMIN_USER="${GRAYLOG_ADMIN_USER:-admin}"
  local ADMIN_PASS="${GRAYLOG_PASSWORD}"

  # Wait for Graylog API
  log "Waiting for Graylog API to be ready at ${API_URL}"
  local attempt=0
  local max_attempts=10
  until curl -fsS -u "${ADMIN_USER}:${ADMIN_PASS}" \
           -H "X-Requested-By: script" \
           "${API_URL}/system/cluster/nodes" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if (( attempt >= max_attempts )); then
      warn "Graylog API not ready after $((10*max_attempts))s; skipping content pack install"
      return 1
    fi
    echo "    Graylog API is not ready yet. Retrying in 10 seconds..."
    sleep 10
  done
  echo "[+] Graylog API is up!"

  # Locate content packs directory
  local PACKS_DIR="$SCRIPT_DIR/content_packs"
  if [[ ! -d "$PACKS_DIR" ]]; then
    warn "No content_packs/ directory found at $PACKS_DIR; nothing to install"
    return 0
  fi

  shopt -s nullglob
  local files=("$PACKS_DIR"/*.json)
  if (( ${#files[@]} == 0 )); then
    warn "No JSON content packs found in $PACKS_DIR; nothing to install"
    return 0
  fi

  for pack in "${files[@]}"; do
    log "Uploading Graylog content pack: $(basename "$pack")"
    # Upload content pack
    local upload_resp
    if ! upload_resp=$(curl -sS -u "${ADMIN_USER}:${ADMIN_PASS}" -X POST \
      -H "Content-Type: application/json" \
      -H "X-Requested-By: script" \
      -d @"$pack" \
      "${API_URL}/system/content_packs"); then
      warn "Failed to upload content pack $(basename "$pack")"
      continue
    fi

    local id
    id=$(echo "$upload_resp" | jq -r '.id // empty')
    if [[ -z "$id" ]]; then
      warn "Could not parse content pack ID from upload response: $upload_resp"
      continue
    fi
    echo "    Content pack uploaded with ID: $id"

    # Install content pack (revision 1 by default)
    local rev=1
    if curl -sS -u "${ADMIN_USER}:${ADMIN_PASS}" -X POST \
         -H "X-Requested-By: script" \
         "${API_URL}/system/content_packs/${id}/${rev}/installations" >/dev/null; then
      echo "[+] Installed content pack ${id} (rev ${rev})"
    else
      warn "Failed to install content pack ${id} (rev ${rev})"
    fi
  done
}

log "Do you want to install SOC-SIEM Graylog content packs from content_packs/? (y/n)"
read -r answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
  install_graylog_content_packs || warn "Some content packs may not have installed"
else
  log "Skipping content pack installation as per user choice"
fi
    