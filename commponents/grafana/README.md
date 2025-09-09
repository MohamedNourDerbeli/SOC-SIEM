# Grafana

Purpose:
- Install Grafana and enforce HTTPS using the shared cert bundle
- Render grafana.ini from env
- Create OpenSearch role/user for Grafana (user: grafna)
- Provision OpenSearch datasource and dashboards

Requirements:
- Cert bundle at commponents/config/wazuh-certificates.tar (must contain ${NODE_NAME}.pem and ${NODE_NAME}-key.pem)
- Wazuh Indexer installed on same host for security tools

Env (.env):
- GRAFANA_DASHBOARD_HOSTNAME (required)
- NODE_NAME (optional; defaults to GRAFANA_DASHBOARD_HOSTNAME)
- WAZUH_INDEXER_IP (required)
- GRAFANA_INDEXER_PASSWORD (optional; auto-generated if missing)
- GRAYLOG_SERVER_HOSTNAME (required for datasource links)
- GRAFANA_ADMIN_PASSWORD (optional)

Install:
- bash commponents/grafana/grafana-install.sh

Verify:
- systemctl status grafana-server
- https://${GRAFANA_DASHBOARD_HOSTNAME}:3000
