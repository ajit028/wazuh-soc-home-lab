# 📘 SANS-Based Wazuh SOC Alert Triage & Incident Response Playbook

**Author:** Ajit Nayak (SOC Analyst / Threat Detection Engineer)  
**Framework:** SANS / NIST SP 800-61 Rev. 2 Incident Handling Process  
**Lab Target:** Wazuh SIEM & XDR Home Lab (`wazuh-soc-home-lab`)  
**Classification:** TLP:CLEAR (Public Security Engineering Standard)  

---

## 📑 Table of Contents
1. [SOC Incident Response Lifecycle Overview](#1-soc-incident-response-lifecycle-overview)
2. [Playbook 1: Credential Dumping & LSASS Harvesting (MITRE T1003)](#2-playbook-1-credential-dumping--lsass-harvesting-mitre-t1003)
3. [Playbook 2: LOLBAS & Obfuscated Scripting Execution (MITRE T1059 / T1105)](#3-playbook-2-lolbas--obfuscated-scripting-execution-mitre-t1059--t1105)
4. [Playbook 3: Multi-Protocol Brute Force & Account Takeover (MITRE T1110)](#4-playbook-3-multi-protocol-brute-force--account-takeover-mitre-t1110)
5. [Playbook 4: Wazuh Active Response Orchestration & Containment](#5-playbook-4-wazuh-active-response-orchestration--containment)
6. [Incident Escalation & Chain of Custody Standard](#6-incident-escalation--chain-of-custody-standard)

---

## 1. SOC Incident Response Lifecycle Overview

```
   ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
   │  1. PREPARATION   │ ───► │ 2. IDENTIFICATION │ ───► │  3. CONTAINMENT   │
   │  Sysmon / Rules   │      │ Alert Validation  │      │ Host Isolation    │
   └───────────────────┘      └───────────────────┘      └───────────────────┘
                                                                   │
                                                                   ▼
   ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
   │ 6. LESSONS LEARNED│ ◄─── │    5. RECOVERY    │ ◄─── │  4. ERADICATION   │
   │ Detection Tuning  │      │ System Validation │      │ Malware / Reg Purge│
   └───────────────────┘      └───────────────────┘      └───────────────────┘
```

---

## 2. Playbook 1: Credential Dumping & LSASS Harvesting (MITRE T1003)

### Alert Context
- **Wazuh Rule IDs:** `100010` (Mimikatz CLI), `100011` (LSASS MiniDump), `100012` (Sysmon Event ID 10 ProcessAccess)
- **Severity:** Critical (Level 14)
- **MITRE ATT&CK:** T1003.001 (LSASS Memory), T1003.002 (Security Account Manager)

### Step 1: Identification & Alert Validation
1. Pivot into Wazuh **Threat Hunting** Dashboard.
2. Filter by `rule.id: (100010 OR 100011 OR 100012)`.
3. Inspect `win.eventdata.sourceImage`, `win.eventdata.targetImage`, `win.eventdata.grantedAccess`, and `win.eventdata.commandLine`.
4. Validate true positive indicators:
   - Command-line containing `sekurlsa::`, `logonpasswords`, `procdump lsass`, or `comsvcs.dll #24`.
   - Non-system binary requesting `0x1010` or `0x1FFFFF` access masks to `C:\Windows\System32\lsass.exe`.

### Step 2: Containment
1. **Network Isolation:** Trigger Wazuh Active Response quarantine or execute host isolation:
   ```powershell
   # Windows Endpoint Isolation via PowerShell
   New-NetFirewallRule -DisplayName "SOC-Quarantine-BlockAll" -Direction Outbound -Action Block -Profile Any
   New-NetFirewallRule -DisplayName "SOC-Quarantine-AllowWazuh" -Direction Outbound -Action Allow -RemoteAddress <WAZUH_SERVER_IP> -RemotePort 1514,1515
   ```
2. **Process Termination:** Kill the parent offending process and suspicious child spawns:
   ```powershell
   Stop-Process -Id <PID> -Force
   ```

### Step 3: Eradication
1. Remove staged memory dump files (`lsass.dmp`, `sam.save`, `system.save` under `C:\Windows\Temp\` or `C:\Users\Public\`).
2. Search for persistence artifacts dropped in `HKLM\SAM` or `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
3. Revoke active Kerberos tickets and force immediate password reset for all accounts logged into the compromised host:
   ```powershell
   klist purge
   ```

### Step 4: Recovery & Validation
1. Re-verify Sysmon Event ID 10 alerts to ensure no subsequent LSASS access attempts.
2. Re-enable network connectivity once telemetry confirms host integrity.
3. Validate Wazuh Agent status: `wazuh-control status`.

---

## 3. Playbook 2: LOLBAS & Obfuscated Scripting Execution (MITRE T1059 / T1105)

### Alert Context
- **Wazuh Rule IDs:** `100020` (Certutil Ingress), `100021` (BITSAdmin), `100022` (MSHTA), `100024` (Obfuscated PowerShell)
- **Severity:** High (Level 12-13)
- **MITRE ATT&CK:** T1059.001, T1105, T1218.005

### Step 1: Identification & Triage
1. Search Wazuh Dashboard for `win.eventdata.parentImage` and inspect the full process lineage:
   ```json
   {
     "win.eventdata.parentImage": "cmd.exe",
     "win.eventdata.image": "powershell.exe",
     "win.eventdata.commandLine": "powershell.exe -NoP -NonI -W Hidden -Enc V3JpdGUtSG9zdC..."
   }
   ```
2. Decode base64 command payload using CyberChef or Python:
   ```bash
   echo "V3JpdGUtSG9zdC..." | base64 -d
   ```
3. Extract C2 IP addresses, dropped file names, or scheduled task names.

### Step 2: Containment
1. Block the external staging URL / C2 IP at the perimeter firewall / Wazuh Active Response:
   ```bash
   /var/ossec/active-response/bin/firewall-drop.sh add - <SUSPICIOUS_C2_IP>
   ```
2. Terminate running script interpreters (`powershell.exe`, `mshta.exe`, `wscript.exe`).

### Step 3: Eradication
1. Delete downloaded payloads from `C:\Windows\Temp\` or `C:\Users\<user>\AppData\Local\Temp\`.
2. Inspect Windows Defender exclusions to verify no blindspots were added:
   ```powershell
   Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
   ```

### Step 4: Recovery
1. Restore modified security configuration.
2. Confirm Sysmon Event ID 1 and Event ID 3 show clean process execution.

---

## 4. Playbook 3: Multi-Protocol Brute Force & Account Takeover (MITRE T1110)

### Alert Context
- **Wazuh Rule IDs:** `100030` (SSH Failures), `100031` (SSH Breach), `100032` (RDP Failures), `100033` (RDP Compromise)
- **Severity:** High / Critical (Level 10-14)
- **MITRE ATT&CK:** T1110.001, T1021.001, T1078.002

### Step 1: Identification & Investigation
1. Identify the attacking IP address (`srcip` or `win.eventdata.ipAddress`).
2. Check if a high-level success alert (`100031` or `100033`) fired immediately following the brute force spike.
3. Check target user accounts targeted in `win.eventdata.targetUserName` / `dstuser`.

### Step 2: Containment
1. Apply automatic IP drop via Wazuh Active Response on the attacking source IP.
2. If successful authentication occurred:
   - Immediately disable the target user account in Active Directory / Local SAM:
     ```powershell
     Disable-LocalUser -Name "CompromisedUser"
     ```
   - Terminate active RDP / SSH sessions:
     ```powershell
     logoff <SessionID>
     ```

### Step 3: Eradication & Recovery
1. Audit logon events (`4624` Type 10 / Type 3) occurring after the breach timestamp.
2. Reset credentials and enforce Multi-Factor Authentication (MFA).
3. Whitelist trusted IP ranges for RDP/SSH management.

---

## 5. Playbook 4: Wazuh Active Response Orchestration & Containment

Wazuh Active Response enables automated and manual script execution upon alert generation.

### Configured Active Response Actions (`ossec.conf`)

```xml
<!-- Automatic Firewall Drop on Brute Force Spike (Rule 100030 / 100032) -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100030, 100032</rules_id>
  <timeout>600</timeout>
</active-response>

<!-- Host Quarantine Script Execution on Mimikatz LSASS Access (Rule 100010) -->
<active-response>
  <command>host-quarantine</command>
  <location>defined-agent</location>
  <agent_id>001</agent_id>
  <rules_id>100010</rules_id>
</active-response>
```

### Active Response Verification Procedure
1. Monitor `/var/ossec/logs/active-responses.log` on the Wazuh Manager:
   ```bash
   tail -f /var/ossec/logs/active-responses.log
   ```
2. Verify firewall rule creation on the endpoint:
   - **Linux:** `iptables -L -n -v | grep DROP`
   - **Windows:** `Get-NetFirewallRule -DisplayName "Wazuh Active Response*"`

---

## 6. Incident Escalation & Chain of Custody Standard

| Severity Level | Response SLA | Escalation Target | Notification Channel |
|---|---|---|---|
| **Critical (Level 13-14)** | < 15 minutes | Tier 2 / Tier 3 Incident Lead | PagerDuty / SOC Hotline / Telegram |
| **High (Level 10-12)** | < 30 minutes | Tier 2 SOC Analyst | SOC Slack / Jira Security Board |
| **Medium (Level 7-9)** | < 2 hours | Tier 1 SOC Analyst | SIEM Alert Queue |
| **Low (Level 1-6)** | < 24 hours | Automation / Daily Review | Threat Intelligence Digest |

### Incident Documentation Template
```markdown
### SOC Incident Triage Report
- **Incident ID:** INC-2026-XXXX
- **Date / Time:** YYYY-MM-DD HH:MM:SS UTC
- **Analyst:** Ajit Nayak
- **Affected Endpoint:** WIN11-LAB (192.168.1.100)
- **Attacking Host:** 192.168.1.50 (Kali Linux)
- **Wazuh Alerts:** 100010 (Mimikatz), 100024 (PowerShell Obfuscation)
- **Root Cause:** Adversary dropped obfuscated cradle via RDP session and attempted LSASS memory dump.
- **Actions Taken:** 
  1. Automated firewall drop executed via Wazuh Active Response.
  2. Compromised user account disabled and sessions terminated.
  3. Dump files in C:\Windows\Temp purged.
- **Status:** Contained & Closed.
```
