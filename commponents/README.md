# Components

This folder contains all deployable components of the SOC-SIEM stack:

- grafana/ — Grafana installer, configs, and provisioning
- graylog/ — Graylog installer, config, and optional content packs
- fluent-bit/ — Fluent Bit installer and config
- wauzh/ — Wazuh suite (Indexer, Dashboard, Manager)
- config/ — Certificate generator and bundle used by other components
- incident-simulation/ — Scripts to simulate security events

Use the root `install.sh` to orchestrate a full installation, or run each component’s installer individually.
