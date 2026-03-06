
---

## ✅ `attack_summary.md`

```markdown
# Attack Summary (Incident Narrative)

> This document summarizes the investigation findings as a timeline-style incident report.  
> All evidence references are derived from Splunk searches in `detection_queries.spl`.

---

## Executive Summary

A public-facing web server was targeted by a single external client IP (`<Suspicious_IP>`) exhibiting non-browser tooling and repeated probing of sensitive paths. Evidence indicates the attacker used automated tools associated with exploitation (e.g., SQL injection), achieved remote command execution via a webshell endpoint, executed a ransomware-like payload, and established outbound C2 communication from the compromised server (`10.10.1.5`) to an external destination (`<Attacker_IP>`). Firewall logs show a high volume of outbound transfer consistent with exfiltration.

---

## Key Indicators Observed

### Recon / Scanning
- Non-browser user agents: `curl`, `wget`, `sqlmap`, `havij`
- Sensitive path probing:
  - `/.env`
  - `/.git*`
  - `phpinfo`

### Exploitation
- SQL injection tooling indicators:
  - `sqlmap`, `havij`
- Time-based SQL injection clues:
  - payload patterns like `SLEEP(5)` (where visible)
  - 504 status behavior consistent with time delay attacks

### Post-Exploitation
- Webshell activity:
  - `shell.php?cmd=*` indicates remote command execution
- Ransomware-like execution:
  - `bunnylock.bin` referenced in command execution path

### Network Confirmation
- Outbound connection from server to attacker destination:
  - firewall logs show `action=ALLOWED`
  - `reason=C2_CONTACT` (if present in dataset)
- High outbound bytes:
  - `sum(bytes_transferred)` indicates large transfer volume

---

## Timeline (Investigation Story)

> Replace time windows with exact times once you run the searches.

### Phase 1 — Initial Recon
- Attacker begins probing sensitive endpoints such as:
  - `/.env`, `/.git`, `phpinfo`
- Most requests return `403/401/404`, indicating blocked or missing resources
- Evidence: sensitive path probe search results (`web_traffic`)

### Phase 2 — Exploitation Attempts (SQL Injection)
- Attacker uses known SQLi tools (`sqlmap`, `havij`)
- HTTP status patterns (including potential `504`) suggest time-based injection attempts
- Evidence: SQL injection user-agent search results

### Phase 3 — Webshell / RCE
- Requests to `shell.php?cmd=...` indicate successful command execution
- Evidence: webshell query results showing command parameter usage

### Phase 4 — Ransomware-Like Payload Execution
- Commands include execution of `bunnylock.bin`
- Behavior indicates malware staging and execution
- Evidence: web traffic paths referencing `bunnylock.bin` execution patterns

### Phase 5 — C2 Contact and Exfiltration
- Compromised server (`10.10.1.5`) initiates outbound connection to `<Attacker_IP>`
- Firewall logs show the connection allowed, potentially flagged as `C2_CONTACT`
- Large outbound transfer volume supports exfiltration hypothesis
- Evidence: firewall pivot + bytes transferred calculation

---

## Impact (Likely)

- Web server compromise with remote command execution capability
- Potential theft of logs/configuration archives (`logs.tar.gz`, `backup.zip`)
- Possible ransomware execution and extortion staging
- Confirmed outbound connection to attacker infrastructure

---

## Containment / Recommendations (What a SOC would do next)

- Block attacker IP `<Suspicious_IP>` at perimeter/WAF
- Isolate server `10.10.1.5` from network
- Rotate secrets / credentials possibly exposed (especially if `/.env` was accessible)
- Hunt for persistence indicators (cron jobs, webshell files, new users)
- Add detections/alerts:
  - requests to `shell.php?cmd=`
  - requests for `/.env`, `/.git`, `phpinfo`
  - non-browser user agents with repeated requests
  - outbound traffic flagged as C2 with high byte transfer

---

## Evidence References

- Queries are stored in: `detection_queries.spl`
- Detection logic / tuning notes: `detection_logic.md`
