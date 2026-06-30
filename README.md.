# SOC Home Lab — Attack Detection & Incident Analysis

A personal cybersecurity home lab built to simulate real-world adversary 
techniques and validate detection capabilities using a Wazuh SIEM. 
All attacks were executed in an isolated virtual environment.

## Lab Architecture

| Component | Role | IP |
|---|---|---|
| Kali Linux 2025.3 | Attacker | 192.168.152.131 |
| Windows 10 (MSEDGEWIN10) | Victim | 192.168.152.129 |
| Wazuh 4.14.5 | SIEM | 192.168.152.130 |

All three VMs communicate over an isolated VMware Host-only network 
(192.168.152.0/24). No traffic leaves the lab environment.

## Tools Used

- **Wazuh 4.14.5** — SIEM, alert correlation, CIS benchmark scanning
- **Kali Linux 2025.3** — Attack platform
- **Metasploit Framework** — Exploitation and credential attack simulation
- **Nmap 7.99** — Network reconnaissance
- **VMware Workstation 16 Pro** — Virtualization

## Incidents Documented

| # | Incident | MITRE Technique | Severity |
|---|---|---|---|
| 01 | WinRM Single Authentication Attempt | T1110 Brute Force | Level 5 |
| 02 | SMB Brute Force + Correlation Alert | T1110 Brute Force | Level 10 |
| 03 | WinRM Wordlist Brute Force | T1110 Brute Force | Level 5–10 |

## Key Findings

- Wazuh successfully detected all authentication-based attacks via 
  Windows Security Event ID 4625
- Rule 60204 (Multiple Windows Logon Failures) auto-escalated to 
  Level 10 when the failure threshold was crossed — simulating a 
  real SOC escalation trigger
- Source IP (192.168.152.131 — Kali) was captured in all alerts, 
  enabling immediate attacker attribution
- CIS Windows 10 Benchmark scan revealed a 27% compliance score 
  (115 passed / 304 failed) — identifying significant hardening gaps

## Detection Gap Noted

Wazuh's default rule for single authentication failures (Rule 60122) 
mapped events to MITRE T1531 (Account Access Removal) — an imprecise 
mapping. A failed login attempt is more accurately T1110 (Brute Force) 
or T1078 (Valid Accounts). The correlation rule (60204) correctly 
identified T1110 once the threshold was crossed. This highlights the 
importance of analyst judgment when interpreting automated 
rule-to-ATT&CK mappings.
