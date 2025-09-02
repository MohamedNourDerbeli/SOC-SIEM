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

mv -n /etc/wazuh-indexer/certs/${NODE_NAME}.pem /etc/wazuh-indexer/certs/wazuh.indexer.pem
mv -n /etc/wazuh-indexer/certs/${NODE_NAME}-key.pem /etc/wazuh-indexer/certs/wazuh.indexer.key

chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# --- Copy opensearch.yml ---
echo "[+] Deploying opensearch.yml..."
cp ./opensearch.yml /etc/wazuh-indexer/opensearch.yml
chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.yml
chmod 640 /etc/wazuh-indexer/opensearch.yml

# --- Enable and start service ---
echo "[+] Enabling and starting Wazuh Indexer..."
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl restart wazuh-indexer

# --- Initialize security ---
echo "[+] Initializing security..."
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

# --- Test connectivity ---
echo "[+] Testing Wazuh Indexer..."
curl -k -u "${WAZUH_INDEXER_USERNAME}:${WAZUH_INDEXER_PASSWORD}" "${WAZUH_INDEXER_URL}" || true
