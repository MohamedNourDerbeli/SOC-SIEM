# Wazuh Dashboard

Purpose:
- Install Wazuh Dashboard 4.12
- Deploy TLS certs from bundle
- Render opensearch_dashboards.yml and set keystore password

Requirements:
- Cert bundle at commponents/config/wazuh-certificates.tar
- Wazuh Indexer reachable

Env (.env):
- WAZUH_DASHBOARD_HOSTNAME (required)
- WAZUH_INDEXER_IP (required)
- WAZUH_KIBANASERVER_PASSWORD (required)
- WAZUH_DASHBOARD_IP (optional; display only)

Install:
- bash commponents/wauzh/wazuh-dashboard/dashborad-install.sh

Verify:
- systemctl status wazuh-dashboard
- https://${WAZUH_DASHBOARD_IP}:443
