# Config & Certificates

Purpose:
- Generate Wazuh TLS certs and bundle them for reuse by components

Scripts:
- generate_certs.sh: renders config from .env and runs certs.sh tool to create certs
- certs.sh: helper tool used by the generator

Inputs:
- .env must define at least:
  - WAZUH_INDEXER_IP, WAZUH_INDEXER_HOSTNAME
  - GRAYLOG_SERVER_IP, GRAYLOG_SERVER_HOSTNAME
  - WAZUH_DASHBOARD_HOSTNAME

Outputs:
- wazuh-certificates/ (certs directory)
- wazuh-certificates.tar (bundle used by other installers)

Run:
- bash commponents/config/generate_certs.sh
