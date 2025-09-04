#!/bin/bash
set -e

# --- Load environment variables ---
ENV_FILE="../../../.env"
NODE_NAME="${WAZUH_DASHBOARD_HOSTNAME}"
DASHBOARD_CONFIG_FILE="/etc/wazuh-dashboard/opensearch_dashboards.yml"
TEMPLATE_FILE="./opensearch_dashboards.yml"
if [ -f "$ENV_FILE" ]; then
    echo "[+] Loading environment variables from $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "[-] $ENV_FILE file not found!"
    exit 1
fi

# --- Install dependencies and Wazuh Dashboard ---
echo "[+] Installing Wazuh Dashboard..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y debhelper tar curl libcap2-bin
    apt-get install -y wazuh-dashboard=4.12.0-1
elif command -v yum >/dev/null 2>&1; then
    yum install -y debhelper tar curl libcap2-bin
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    yum install -y wazuh-dashboard=4.12.0-1
else
    echo "[-] Neither apt-get nor yum found!"
    exit 1
fi


# --- Certificates setup ---
echo "[+] Setting up certificates..."

mkdir /etc/wazuh-dashboard/certs
tar -xf ../../config/wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ \
    "./${NODE_NAME}.pem" \
    "./${NODE_NAME}-key.pem" \
    ./root-ca.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

# Define the specific variables the template needs
VARS_TO_SUBSTITUTE='${WAZUH_INDEXER_IP} ${NODE_NAME}'

# Use envsubst to replace the variables in the template and write the final config
envsubst "$VARS_TO_SUBSTITUTE" < "$TEMPLATE_FILE" | sudo tee "$DASHBOARD_CONFIG_FILE" > /dev/null

echo "${WAZUH_KIBANASERVER_PASSWORD}" | sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password

# --- Enable and start service ---
echo "[+] Enabling and starting Wazuh Dashboard..."
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

echo "[+] Wazuh Dashboard installation and configuration completed."
echo "    - Access the dashboard at: https://${WAZUH_DASHBOARD_IP}:443"
echo "    - Login: admin"
echo "    - Password: ${WAZUH_INDEXER_PASSWORD}"