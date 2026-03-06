# Detection Logic & Engineering Notes

This document explains the detection reasoning, risk assessment, tuning guidance, and operationalization strategy for the web attack investigation project.

The objective is to convert hunting queries into structured detection engineering artifacts aligned with SOC best practices.

---

# 1. Detection Goals

- Detect reconnaissance against public-facing web applications
- Identify exploitation attempts (SQL injection)
- Detect post-exploitation behavior (webshell / RCE)
- Correlate web logs with firewall telemetry
- Reduce false positives using structured tuning logic
- Prepare detections for production deployment

---

# 2. Detection 1 — Suspicious User Agents (Non-Browser Tooling)

## Objective

Identify automated exploitation tools accessing the web server.

## Why It Works

Legitimate traffic typically comes from browsers such as:
- Mozilla
- Chrome
- Safari
- Firefox

Attackers frequently use:
- curl
- wget
- sqlmap
- havij

Filtering out common browsers highlights automation and scanning activity.

## SPL Logic

```spl
index=main sourcetype=web_traffic
| search user_agent!=*Mozilla* user_agent!=*Chrome* user_agent!=*Safari* user_agent!=*Firefox*
| stats count by client_ip
| sort -count
```

## Risk Level

Medium on its own  
High when correlated with sensitive endpoint access

## Common False Positives

- CI/CD scripts
- Monitoring tools
- Internal vulnerability scanners
- Authorized penetration testing

## Tuning Strategy

- Trigger only if count exceeds threshold (e.g., 20+ events in 10 minutes)
- Correlate with suspicious paths
- Maintain allowlist of known scanner IP ranges

---

# 3. Detection 2 — Sensitive File Probing

## Objective

Detect reconnaissance attempts targeting sensitive resources.

High-signal targets:
- /.env
- /.git
- phpinfo
- Path traversal patterns ("..")

## SPL Logic

```spl
sourcetype=web_traffic
AND path IN ("/.env", "/*phpinfo*", "/.git*")
| table _time, client_ip, path, user_agent, status
```

## Risk Level

High if repeated  
Critical if combined with suspicious user agents

## False Positives

- Approved security testing
- Red team exercises

## Tuning Strategy

- Alert only after repeated attempts
- Require multiple sensitive endpoints targeted
- Correlate with non-browser user agents

---

# 4. Detection 3 — SQL Injection Tooling

## Objective

Detect automated SQL injection activity.

## Indicators

- User agents: sqlmap, havij
- Repeated parameter manipulation
- Status codes 500 or 504
- Payload strings such as SLEEP(5)

## SPL Logic

```spl
sourcetype=web_traffic
client_ip="<Suspicious_IP>"
AND user_agent IN ("*sqlmap*", "*Havij*")
| table _time, path, user_agent, status
```

## Risk Level

High

## False Positives

- Authorized penetration testing

## Tuning Strategy

- Require multiple attempts within short time window
- Correlate with sensitive endpoint probing
- Add IP reputation enrichment if available

---

# 5. Detection 4 — Webshell / Remote Code Execution

## Objective

Detect remote command execution via web-accessible script.

## Indicator

- shell.php?cmd=

## SPL Logic

```spl
sourcetype=web_traffic
client_ip="<Suspicious_IP>"
AND path="*shell.php?cmd=*"
| table _time, path, user_agent, status
```

## Risk Level

Critical

## False Positives

Extremely rare in legitimate production environments

## Response Recommendation

- Immediate host isolation
- Forensic evidence collection
- Credential rotation

---

# 6. Detection 5 — Malware / Ransomware Execution

## Indicator

Execution of suspicious binary such as bunnylock.bin via webshell.

## SPL Logic

```spl
sourcetype=web_traffic
client_ip="<Suspicious_IP>"
AND path="*bunnylock.bin*"
| table _time, path, user_agent, status
```

## Risk Level

Critical

## Response Recommendation

Escalate to Incident Response team immediately.

---

# 7. Detection 6 — Command-and-Control (C2)

## Objective

Confirm outbound communication from compromised server to attacker infrastructure.

## SPL Logic

```spl
sourcetype=firewall_logs
src_ip="10.10.1.5"
AND dest_ip="<Attacker_IP>"
AND action="ALLOWED"
| table _time, protocol, src_ip, dest_ip, dest_port, reason
```

## Risk Level

Critical when correlated with exploitation indicators

## False Positives

- New vendor IP addresses
- Cloud services
- Legitimate outbound traffic

## Tuning Strategy

- Correlate with web compromise events
- Check destination IP reputation
- Alert only if linked to suspicious activity

---

# 8. Detection 7 — Data Exfiltration

## Objective

Quantify abnormal outbound data transfer.

## SPL Logic

```spl
sourcetype=firewall_logs
src_ip="10.10.1.5"
AND dest_ip="<Attacker_IP>"
AND action="ALLOWED"
| stats sum(bytes_transferred) as total_bytes by src_ip, dest_ip
```

## Risk Level

High

## Tuning Strategy

- Establish baseline outbound traffic
- Alert when volume exceeds threshold (e.g., 3x normal daily average)
- Correlate with webshell execution events

---

# 9. Cross-Detection Tuning Strategy

To reduce false positives:

- Use threshold-based alerting
- Correlate multiple signals before alerting
- Maintain allowlists
- Apply enrichment (reputation, ASN, geolocation)
- Continuously refine based on SOC feedback

Detection engineering is iterative and requires ongoing refinement.

---

# 10. Operationalization Plan

To productionize these detections:

1. Convert SPL queries into Saved Searches
2. Assign severity levels:
   - Medium: Suspicious user agents
   - High: SQL injection or sensitive probing
   - Critical: Webshell or C2 detection
3. Add time windows and event thresholds
4. Create SOC runbooks for response
5. Monitor false positive rate and refine detections

---

# 11. MITRE ATT&CK Mapping

- T1190 — Exploit Public-Facing Application
- T1505.003 — Web Shell
- T1059 — Command and Scripting Interpreter
- T1071 — Application Layer Protocol
- T1041 — Exfiltration Over C2 Channel

---

# Final Note

This document transforms simple log queries into structured detection engineering artifacts aligned with real-world SOC workflows and modern threat detection practices.
