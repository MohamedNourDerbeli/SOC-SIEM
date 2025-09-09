# Graylog

Purpose:
- Install MongoDB 7 and Graylog 6
- Import Wazuh root CA into Graylog truststore
- Create internal OpenSearch user for Graylog
- Render server.conf from env
- Optional: install content packs in content_packs/

Requirements:
- Ubuntu 22.04 (apt)
- Cert bundle at commponents/config/wazuh-certificates.tar

Env (.env):
- PASSWORD_SECRET (required)
- GRAYLOG_PASSWORD (required; used to compute ROOT_PASSWORD_SHA2)
- WAZUH_INDEXER_IP (required)
- GRAYLOG_SERVER_IP (recommended; for URL hints)

Install:
- bash commponents/graylog/graylog-install.sh

Verify:
- systemctl status mongod
- systemctl status graylog-server
- http://${GRAYLOG_SERVER_IP}:9000
