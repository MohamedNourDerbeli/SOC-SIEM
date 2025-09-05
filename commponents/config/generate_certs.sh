#!/bin/bash

set -Eeuo pipefail
IFS=$'\n\t'

log() { echo -e "[+] $*"; }
die() { echo -e "[-] $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."; }

ENV_FILE="../../.env"
TEMPLATE_FILE="./config.yml"
OUTPUT_FILE="./generated_config.yml"

[[ -f "$ENV_FILE" ]] || die "Environment file not found at '$ENV_FILE'"
set -a; source "$ENV_FILE"; set +a
log "Loaded configuration from $ENV_FILE"

REQUIRED_VARS=(
    "WAZUH_INDEXER_IP" "WAZUH_INDEXER_HOSTNAME"
    "GRAYLOG_SERVER_IP" "GRAYLOG_SERVER_HOSTNAME"
    "WAZUH_DASHBOARD_HOSTNAME"
)
for var in "${REQUIRED_VARS[@]}"; do
    [[ -n "${!var:-}" ]] || die "Required variable '$var' is not set in your .env file."
done

WAZUH_DASHBOARD_IP=${WAZUH_DASHBOARD_IP:-$GRAYLOG_SERVER_IP}

log "Generating $OUTPUT_FILE from $TEMPLATE_FILE..."
require_cmd envsubst

export WAZUH_INDEXER_IP WAZUH_INDEXER_HOSTNAME
export GRAYLOG_SERVER_IP GRAYLOG_SERVER_HOSTNAME
export WAZUH_DASHBOARD_IP WAZUH_DASHBOARD_HOSTNAME

envsubst '${WAZUH_INDEXER_IP} ${WAZUH_INDEXER_HOSTNAME} ${GRAYLOG_SERVER_IP} ${GRAYLOG_SERVER_HOSTNAME} ${WAZUH_DASHBOARD_IP} ${WAZUH_DASHBOARD_HOSTNAME}' \
    < "$TEMPLATE_FILE" > "$OUTPUT_FILE"

log "Running cert generation tool"
bash ./certs.sh -A

log "Packing certificates"
require_cmd tar
[[ -d ./wazuh-certificates ]] || die "Expected ./wazuh-certificates directory not found"
tar -cf ./wazuh-certificates.tar -C ./wazuh-certificates/ .

log "Certificate generation completed."