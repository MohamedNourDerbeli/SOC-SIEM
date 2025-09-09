# Wazuh Manager

Purpose:
- Install Wazuh Manager 4.12
- Render ossec.conf with Indexer endpoint
- Configure authd password
- Deploy shared agent configs (Linux/Windows) if present

Env (.env):
- WAZUH_MANAGER_IP (required)
- WAZUH_MANAGER_HOSTNAME (optional)
- WAZUH_INDEXER_IP (required)
- WAZUH_DASHBOARD_IP (optional)
- WAZUH_MANAGER_PASSWORD (required; authd password)

Install:
- bash commponents/wauzh/wazuh-manager/manager-install.sh

Verify:
- systemctl status wazuh-manager
- tail -n 200 /var/ossec/logs/ossec.log
