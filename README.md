# Advanced Open-Source SIEM & SOC Automation Project

This repository contains a complete, automated deployment of a powerful, open-source Security Information and Event Management (SIEM) stack. The entire infrastructure is built from the ground up and managed as code, demonstrating a professional approach to modern security operations and DevOps (DevSecOps).

This project goes beyond a simple installation, creating a resilient, scalable, and feature-rich security monitoring platform suitable for a home lab, small business, or as a comprehensive portfolio piece showcasing advanced automation skills.

*You can add your primary architecture diagram here.*
`![Architecture Diagram](./architecture/SIEM-STACK.png)`

---

## The Vision: What Problem This Project Solves

In today's threat landscape, effective security monitoring is essential. However, commercial SIEM solutions can be prohibitively expensive, and default open-source installations are often not configured for optimal performance, security, or real-world threat detection.

This project solves that problem by providing a **fully automated blueprint** for deploying a production-grade, open-source Security Operations Center (SOC) infrastructure. It addresses several key challenges:

*   **Complexity:** It automates the complex installation and integration of multiple best-in-class security tools (Wazuh, Graylog, etc.) into a single, cohesive system.
*   **Configuration as Code:** It eliminates manual setup. Every aspect of the configuration—from the Wazuh manager's rules to Graylog's parsing pipelines—is version-controlled in this repository, ensuring consistency and repeatability.
*   **Security Hardening:** The deployment is not just about installation; it includes creating dedicated service users, managing credentials securely via a central `.env` file, and implementing best practices for inter-component communication.
*   **Enhanced Detection:** The system is pre-loaded with advanced detection rules from trusted sources like SOCFortress, immediately elevating its capabilities beyond the default ruleset.

---

## Core Components & Architecture

The SIEM is built on a foundation of powerful and widely respected open-source tools, each with a specific role. The architecture is designed for modularity and scalability.

*   **Wazuh:** The core of our endpoint security. It acts as the XDR (Extended Detection and Response) platform, providing host-based intrusion detection (HIDS), file integrity monitoring (FIM), vulnerability detection, and security configuration assessment (SCA).
*   **Graylog:** A centralized log management and analysis platform. It ingests, parses, and enriches logs from a wide variety of sources (like firewalls), not just Wazuh alerts. This provides a single pane of glass for all system and network events.
*   **Wazuh Indexer (OpenSearch):** The high-performance, distributed search and analytics engine that serves as the central data store for both Wazuh and Graylog.
*   **MongoDB:** The configuration database for the Graylog server.
*   **Fluent Bit:** A lightweight, high-performance log shipper. In our decoupled architecture, it is responsible for reliably forwarding Wazuh alerts to the Graylog input, enhancing resilience.

### Data Flow

1.  **Wazuh Agents** collect security data from endpoints and send it to the **Wazuh Manager**.
2.  The **Wazuh Manager** analyzes the data, generates alerts, and writes them to a local `alerts.json` file.
3.  **Fluent Bit** tails this JSON file and forwards the alerts to a dedicated input on the **Graylog** server.
4.  **Graylog** processes, normalizes, and enriches these logs using custom pipelines and stores them in the **Wazuh Indexer**.
5.  Analysts can then use the **Wazuh Dashboard** to visualize XDR data and the **Graylog UI** to analyze all ingested logs from a single, unified data store.

---

## Key Features & Professional Practices

This project isn't just a collection of tools; it's a demonstration of professional deployment and management techniques.

*   **Fully Automated Deployment:** The entire stack is designed to be deployed from scratch using a master script, driven by a central `.env` configuration file.
*   **Configuration Templating:** All major configuration files (`ossec.conf`, `server.conf`, etc.) are managed as clean `template` files, separating logic from configuration data. This is a core principle of Infrastructure as Code.
*   **Centralized & Secure Credential Management:** No default passwords are used. All passwords, IP addresses, and API keys are defined in the central **`.env`** file. This file is pre-populated with secure, randomly generated defaults and is intended to be edited by the user before deployment. **Crucially, it is ignored by Git to prevent secrets from ever being committed.**
*   **Dedicated Service Accounts:** Following the Principle of Least Privilege, dedicated users (e.g., `graylog`) are created with the minimum necessary permissions for inter-service communication.
*   **Advanced Rule Management:** The system includes not only custom-written rules but also integrates the SOCFortress ruleset for enhanced threat detection, all managed within the repository.
*   **Configuration as Code for Graylog:** Uses Graylog Content Packs to automatically deploy inputs, streams, and pipelines, ensuring the application layer is also configured as code.

---

## Project Structure

The repository is organized by component, making it modular and easy to navigate.

*   `├── components/`: Contains the installation logic, configuration templates, and rules for each major tool.
    *   `├── graylog/`: Scripts and templates for the Graylog server.
    *   `├── wazuh/`: Scripts, templates, and rules for the Wazuh Manager, Indexer, and Dashboard.
    *   `├── fluentbit/`: (WIP) Configuration for the log shipper.
*   `├── config/`: Centralized configuration artifacts, such as the master certificate bundle.
*   `├── .env`: **The master configuration file for the project.** The user must review and fill out this file before running any installation scripts. It contains all passwords, IP addresses, and other variables needed for the deployment.
*   `└── .gitignore`: Ensures that sensitive files (like the user-modified `.env`) and generated files (like `merged.mg`) are never committed to the repository.

This structure allows for clear separation of concerns and makes the project scalable for adding new components in the future.
