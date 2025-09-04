#!/bin/bash
set -e

# --- Load environment variables ---
ENV_FILE="../../../.env"
if [ -f "$ENV_FILE" ]; then
    echo "[+] Loading environment variables from $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "[-] $ENV_FILE file not found!"
    exit 1
fi

# --- Install dependencies and Wazuh Indexer ---
echo "[+] Installing Wazuh Indexer..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y debconf adduser procps gnupg apt-transport-https curl pwgen
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        | tee /etc/apt/sources.list.d/wazuh.list
    apt-get update
    apt-get install -y wazuh-indexer=4.12.0-1
elif command -v yum >/dev/null 2>&1; then
    yum install -y coreutils curl
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    yum install -y wazuh-indexer=4.12.0-1
else
    echo "[-] Neither apt-get nor yum found!"
    exit 1
fi

# --- Certificates setup ---
echo "[+] Setting up certificates..."
NODE_NAME="${WAZUH_INDEXER_HOSTNAME}"

mkdir -p /etc/wazuh-indexer/certs
tar -xf ../../config/wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ \
    "./${NODE_NAME}.pem" \
    "./${NODE_NAME}-key.pem" \
    ./admin.pem \
    ./admin-key.pem \
    ./root-ca.pem


chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# --- Copy opensearch.yml ---
echo "[+] Deploying opensearch.yml..."

VARS_TO_SUBSTITUTE='${WAZUH_INDEXER_HOSTNAME}'
TEMPLATE_FILE="./opensearch.yml"
DASHBOARD_CONFIG_FILE="/etc/wazuh-indexer/opensearch.yml"

# Use envsubst to replace the variables in the template and write the final config
envsubst "$VARS_TO_SUBSTITUTE" < "$TEMPLATE_FILE" | sudo tee "$DASHBOARD_CONFIG_FILE" > /dev/null


chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.yml
chmod 640 /etc/wazuh-indexer/opensearch.yml


# --- Ensure LimitMEMLOCK is set ---
echo "[+] Ensuring LimitMEMLOCK=infinity in systemd service..."
SERVICE_FILE="/usr/lib/systemd/system/wazuh-indexer.service"

if ! grep -q "^LimitMEMLOCK=infinity" "$SERVICE_FILE"; then
    sed -i '/^\[Service\]/a LimitMEMLOCK=infinity' "$SERVICE_FILE"
fi


# --- Enable and start service ---
echo "[+] Enabling and starting Wazuh Indexer..."
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer


# --- Initialize security ---
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

# --- Test connectivity ---
echo "[+] Testing Wazuh Indexer..."
until curl -k -u admin:admin "https://${WAZUH_INDEXER_IP}:9200" > /dev/null 2>&1; do
    echo "    Wazuh Indexer is not ready yet. Retrying in 5 seconds..."
    sleep 5
done

echo "[+] Wazuh Indexer is up!"

ADMIN_HASH=$(/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${WAZUH_INDEXER_PASSWORD}" | tail -n 1 )
KIBANA_HASH=$(/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${WAZUH_KIBANASERVER_PASSWORD}" | tail -n 1)
GRAYLOG_HASH=$(/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "${GRAYLOG_PASSWORD}" | tail -n 1)
TEMPLATE_FILE="./internal_users.yml"
INTERNAL_CONFIG_FILE="/tmp/internal_users_update.yml"

# Define the specific variables the template needs
VARS_TO_SUBSTITUTE='${ADMIN_HASH} ${KIBANA_HASH} ${GRAYLOG_HASH}'

envsubst "$VARS_TO_SUBSTITUTE" < "$TEMPLATE_FILE" | sudo tee "$INTERNAL_CONFIG_FILE" > /dev/null



sudo JAVA_HOME=/usr/share/wazuh-indexer/jdk \
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -f "$INTERNAL_CONFIG_FILE" \
  -t internalusers \
  -icl -nhnv \
  -h "${WAZUH_INDEXER_IP}" \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem

# Clean up the temporary file
rm -f "$INTERNAL_CONFIG_FILE"

echo "[+] Wazuh Indexer is up!"

curl -k -u admin:"$WAZUH_INDEXER_PASSWORD" "https://${WAZUH_INDEXER_IP}:9200"