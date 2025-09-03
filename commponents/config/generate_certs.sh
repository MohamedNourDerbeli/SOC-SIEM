#!/bin/bash

# This script generates the config.yml required by the wazuh-certs-tool.sh
# by reading variables from the main .env file.

# --- Configuration ---
ENV_FILE="../../.env"
TEMPLATE_FILE="./config.yml"
OUTPUT_FILE="./generated_config.yml"

# --- Pre-flight Checks ---
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: Environment file not found at '$ENV_FILE'"
    echo "Please run 'cp .env.example .env' in the root directory first."
    exit 1
fi

# --- Load Environment Variables ---
set -a
source "$ENV_FILE"
set +a
echo "Loaded configuration from $ENV_FILE"

# --- Variable Validation ---
# Check that all necessary variables are loaded from the .env file.
REQUIRED_VARS=(
    "WAZUH_INDEXER_IP" "WAZUH_INDEXER_HOSTNAME"
    "GRAYLOG_SERVER_IP" "GRAYLOG_SERVER_HOSTNAME"
    "WAZUH_DASHBOARD_HOSTNAME"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: Required variable '$var' is not set in your .env file."
        echo "Please check your configuration."
        exit 1
    fi
done

# For the dashboard IP, we can default to the manager's IP if it's not set.
WAZUH_DASHBOARD_IP=${WAZUH_DASHBOARD_IP:-$GRAYLOG_SERVER_IP}

# --- Generate config.yml from Template ---
echo "Generating $OUTPUT_FILE from $TEMPLATE_FILE..."

if ! command -v envsubst &> /dev/null; then
    echo "Error: 'envsubst' command not found. Please install 'gettext' package (e.g., 'sudo apt-get install gettext')."
    exit 1
fi

# Export the variables so envsubst can see them
export WAZUH_INDEXER_IP WAZUH_INDEXER_HOSTNAME
export GRAYLOG_SERVER_IP GRAYLOG_SERVER_HOSTNAME
export WAZUH_DASHBOARD_IP WAZUH_DASHBOARD_HOSTNAME

VARS_TO_SUBSTITUTE='${WAZUH_INDEXER_IP} ${WAZUH_INDEXER_HOSTNAME} ${GRAYLOG_SERVER_IP} ${GRAYLOG_SERVER_HOSTNAME} ${WAZUH_DASHBOARD_IP} ${WAZUH_DASHBOARD_HOSTNAME}'
envsubst "$VARS_TO_SUBSTITUTE" < "$TEMPLATE_FILE" > "$OUTPUT_FILE"

bash ./certs.sh -A

tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .

echo "Certificate generation completed."