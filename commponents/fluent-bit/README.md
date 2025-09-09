# Fluent Bit

Purpose:
- Install Fluent Bit using bundled installer script
- Render fluent-bit.conf to forward logs to Graylog

Env (.env):
- GRAYLOG_SERVER_HOSTNAME (required)

Install:
- bash commponents/fluent-bit/fluent-install.sh

Verify:
- systemctl status fluent-bit
- tail -n 100 /var/log/flu* (or journalctl -u fluent-bit)
