# SOCFortress Rules Runner

Purpose:
- Replace existing Wazuh rules with SOCFortress curated rules

Warning:
- This will overwrite custom rules. Back up before running.

Run:
- sudo bash rules/socfortress/wazuh_socfortress_rules.sh [-y]

Verify:
- tail -n 200 /var/ossec/logs/ossec.log
- Ensure service is healthy after restart
