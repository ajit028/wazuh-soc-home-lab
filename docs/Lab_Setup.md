# Wazuh SOC Home Lab Setup Guide

## Overview

This document describes the deployment process of the Wazuh-based Security Operations Center (SOC) Home Lab.

---

# Lab Environment

| Component | Operating System | Purpose |
|-----------|------------------|----------|
| Wazuh Server | Ubuntu Server 24.04 LTS | SIEM Platform |
| Endpoint | Windows 11 | Monitoring Target |
| Attacker | Kali Linux | Attack Simulation |
| Hypervisor | VMware Workstation | Virtualization |

---

# Network Configuration

| Machine | IP Address |
|----------|------------|
| Ubuntu (Wazuh Server) | 192.168.15.128 |
| Windows 11 Endpoint | 192.168.15.129 |
| Kali Linux | 192.168.15.130 |

---

# Components Installed

- Wazuh Manager
- Wazuh Dashboard
- Wazuh Indexer
- Wazuh Agent
- Microsoft Sysmon
- VMware Tools
- FreeRDP

---

# Attack Scenarios

The following attack simulations were performed:

1. PowerShell Execution
2. Account Discovery
3. Registry Modification
4. Application Shimming
5. Windows Service Creation
6. RDP Lateral Movement

---

# Detection Workflow

Attack Simulation
        │
        ▼
Windows 11 Endpoint
        │
        ▼
Sysmon Event Generation
        │
        ▼
Wazuh Agent
        │
        ▼
Wazuh Manager
        │
        ▼
Indexer
        │
        ▼
Dashboard
        │
        ▼
Threat Hunting
        │
        ▼
MITRE ATT&CK Mapping

---

# Skills Demonstrated

- SIEM Deployment
- Wazuh Administration
- Sysmon Configuration
- Windows Event Monitoring
- Threat Hunting
- MITRE ATT&CK Analysis
- Incident Investigation
- Log Correlation
- Detection Engineering

---

# Repository Structure

```
Wazuh-SOC-Home-Lab
├── architecture
├── attack-scenarios
├── configs
├── docs
├── screenshots
├── LICENSE
└── README.md
```

---

# Author

Ajit Nayak

Bachelor of Technology

Computer Science and Engineering

Government College of Engineering, Kalahandi