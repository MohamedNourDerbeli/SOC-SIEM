# Wazuh Indexer (OpenSearch)

Purpose:
- Install Wazuh Indexer 4.12
- Deploy TLS certs from bundle
- Render opensearch.yml
- Initialize security and set internal users (admin, kibanaserver, graylog)

Requirements:
- Cert bundle at commponents/config/wazuh-certificates.tar with host certs for ${WAZUH_INDEXER_HOSTNAME}

Env (.env):
- WAZUH_INDEXER_HOSTNAME (required)
- WAZUH_INDEXER_IP (required)
- WAZUH_INDEXER_PASSWORD (required)
- WAZUH_KIBANASERVER_PASSWORD (required)
- GRAYLOG_PASSWORD (required)

Install:
- bash commponents/wauzh/wazuh-indexer/indexer-install.sh

Verify:
- systemctl status wazuh-indexer
- curl -k -u admin:admin https://${WAZUH_INDEXER_IP}:9200
