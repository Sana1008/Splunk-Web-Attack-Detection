# Web Attack Detection & C2 Investigation Using Splunk (Detection Engineering Case Study)

> **Focus:** Detection Engineering • Threat Hunting • Incident Investigation  
> **Tools:** Splunk (SPL) • Web Logs • Firewall Logs  
> **Techniques:** SQL Injection → Webshell/RCE → C2 Contact → Data Exfiltration

---

## Overview

This project demonstrates a detection engineering workflow using **Splunk SPL** to investigate a simulated compromise of a public-facing web server. The investigation begins with abnormal HTTP requests and suspicious user agents, then pivots into exploitation indicators (SQLi), post-exploitation activity (webshell/RCE), and finishes with network confirmation of **C2 communication** and **data exfiltration** using firewall telemetry.

This repo is designed to be:
- **Portfolio-ready** (recruiter friendly)
- **Reusable** (placeholders + structured logic)
- **Detection-focused** (not just “lab completion”)

---

## Scenario Summary (Simulated / Lab)

A web server receives:
- Requests to sensitive endpoints like `/.env`, `/.git*`, and `phpinfo`
- Suspicious user agents such as `curl`, `wget`, `sqlmap`, and `havij`
- Indicators of SQL injection and command execution via webshell behavior
- Outbound firewall logs indicating **C2 contact** and high data transfer volumes

> IPs are intentionally placeholdered as `<Suspicious_IP>` / `<Attacker_IP>` to keep this repo shareable.

---

## Data Sources

### `sourcetype=web_traffic`
Fields used:
- `client_ip` — attacker source address
- `user_agent` — browser/tool fingerprints
- `path` — requested URI
- `status` — HTTP response code
- `_time` — event timestamp

### `sourcetype=firewall_logs`
Fields used:
- `src_ip`, `dest_ip`, `dest_port`
- `action`, `reason`
- `bytes_transferred`

---

## Repository Structure

- `README.md` — project overview + how to use  
- `detection_queries.spl` — SPL detections and hunts (copy/paste ready)  
- `attack_summary.md` — narrative timeline (what happened, when, and evidence)  
- `detection_logic.md` — detection rationale, tuning, false positives, MITRE mapping  
- `screenshots/` — optional screenshots for proof (recommended)

---

## Investigation Workflow (High Level)

1. Identify web traffic sourcetypes and baseline activity
2. Filter non-browser user agents and find standout `client_ip`
3. Confirm probing for sensitive resources (`/.env`, `/.git`, `phpinfo`)
4. Confirm SQL injection tooling (`sqlmap`, `havij`) and suspicious patterns
5. Detect webshell execution (`shell.php?cmd=...`) and malware execution (`bunnylock.bin`)
6. Pivot to firewall logs to confirm outbound C2 communication
7. Quantify exfiltration via `bytes_transferred`

---

## MITRE ATT&CK (Suggested)

- **T1190** — Exploit Public-Facing Application  
- **T1505.003** — Web Shell  
- **T1059** — Command and Scripting Interpreter  
- **T1071** — Application Layer Protocol  
- **T1041** — Exfiltration Over C2 Channel

---

## How To Run (Copy/Paste)

1. Open Splunk Search
2. Start with:
   - `index=main sourcetype=web_traffic`
   - `index=main sourcetype=firewall_logs`
3. Copy/paste the queries from:
   - `detection_queries.spl`
4. Replace placeholders:
   - `<Suspicious_IP>`
   - `<Attacker_IP>`
   - `10.10.1.5` (if your compromised host differs)

---

## What This Project Demonstrates

- Threat hunting mindset (identify, narrow, confirm)
- SIEM proficiency (SPL + correlation)
- Incident investigation workflow
- Detection engineering discipline (logic + tuning + false positives)
- Strong portfolio signal for:
  - SOC / Threat Detection
  - Detection Engineering
  - Security Analytics
  - Incident Response

---

## Disclaimer

This project uses simulated/lab data and is for educational and portfolio purposes only. Do not use these techniques to target real systems. Always follow legal and organizational policies.
