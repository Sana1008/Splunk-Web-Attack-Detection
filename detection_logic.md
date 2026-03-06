# Detection Logic & Engineering Notes

> This document explains *why* each detection works, how to tune it, and common false positives.  
> Goal: convert “log analysis” into **defensible detection engineering**.

---

## Detection Goals

1. Detect recon attempts to sensitive files
2. Identify exploitation activity (SQLi tooling and patterns)
3. Detect webshell usage and remote command execution
4. Correlate host compromise with outbound network behaviors (C2/exfiltration)
5. Reduce false positives with tuning guidance

---

## Detection 1 — Suspicious User Agents (Non-Browser Tooling)

### Why It Works
Attackers commonly use low-level tooling such as `curl`, `wget`, and offensive scanners that identify themselves (`sqlmap`, `havij`). Filtering out common browsers surfaces automation and exploitation attempts.

### SPL (Example)
```spl
index=main sourcetype=web_traffic
| search user_agent!=*Mozilla* user_agent!=*Chrome* user_agent!=*Safari* user_agent!=*Firefox*
| stats count by client_ip
| sort -count
