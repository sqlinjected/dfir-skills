---
name: log-analysis
description: Analyze system and security logs (auth.log, syslog, Windows EVTX, Apache/Nginx, JSON logs). Detect brute force, lateral movement, privilege escalation, and anomalous activity.
argument-hint: <path-to-log-file-or-directory>
allowed-tools: Bash Read Write Grep Glob
---

# Log Analysis

You are performing security log analysis. Systematically parse, correlate, and analyze log files to detect malicious or anomalous activity. Validate every finding before reporting.

## Target

Log file or directory: `$ARGUMENTS`

## Pre-flight: Identify Log Type

First, determine what kind of logs you're working with:

```bash
file <target>
head -20 <target>
```

Supported log types and their analysis approaches:

### 1. Linux Auth Logs (auth.log, secure)

```bash
# Failed authentication attempts - brute force detection
grep -i "failed\|failure\|invalid" <logfile> | awk '{print $1,$2,$3,$NF}' | sort | uniq -c | sort -rn | head -30

# Successful logins after failures (potential compromise)
grep -i "accepted\|session opened" <logfile> | awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -rn | head -30

# Sudo usage
grep -i "sudo:" <logfile> | grep -v "pam_unix" | head -50

# User/group modifications
grep -iE "useradd|usermod|groupadd|passwd|adduser" <logfile> | head -30

# SSH activity
grep -i "sshd" <logfile> | grep -iE "accepted|failed|invalid|disconnect" | head -50
```

**Validation**: For brute force findings, confirm:
- More than 5 failed attempts from a single source within 5 minutes
- Check if a successful login follows the failures (indicates compromise)
- Cross-reference the source IP across different log entries

### 2. Windows Event Logs (EVTX)

If the file is EVTX format, use python3 to parse:

```python
#!/usr/bin/env python3
import Evtx.Evtx as evtx
import Evtx.Views as evtx_views
import sys, xml.etree.ElementTree as ET

with evtx.Evtx(sys.argv[1]) as log:
    for record in log.records():
        root = ET.fromstring(record.xml())
        # Extract EventID, TimeCreated, etc.
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        event_id = root.find('.//ns:EventID', ns)
        time_created = root.find('.//ns:TimeCreated', ns)
        if event_id is not None:
            eid = event_id.text
            ts = time_created.get('SystemTime') if time_created is not None else 'N/A'
            print(f"{ts} EventID={eid}")
```

Key Event IDs to hunt for:
| Event ID | Meaning | Log |
|----------|---------|-----|
| 4624 | Successful logon | Security |
| 4625 | Failed logon | Security |
| 4648 | Logon with explicit credentials | Security |
| 4672 | Special privileges assigned | Security |
| 4688 | Process creation | Security |
| 4697 | Service installed | Security |
| 4698 | Scheduled task created | Security |
| 4720 | User account created | Security |
| 4732 | Member added to security group | Security |
| 7045 | New service installed | System |
| 1 | Process creation (Sysmon) | Sysmon |
| 3 | Network connection (Sysmon) | Sysmon |
| 11 | File creation (Sysmon) | Sysmon |
| 1102 | Audit log cleared | Security |

**Validation**: Correlate events by Logon ID — a 4624 followed by 4688 with the same Logon ID confirms a user ran a specific process.

### 3. Web Server Logs (Apache/Nginx)

```bash
# Top requesting IPs
awk '{print $1}' <logfile> | sort | uniq -c | sort -rn | head -20

# HTTP status code distribution
awk '{print $9}' <logfile> | sort | uniq -c | sort -rn

# 4xx/5xx errors by path (attack surface probing)
awk '$9 ~ /^[45]/ {print $9, $7}' <logfile> | sort | uniq -c | sort -rn | head -30

# Potential SQL injection attempts
grep -iE "(union.*select|or.*1.*=.*1|drop.*table|insert.*into|' *or *'|%27|%2527)" <logfile> | head -20

# Potential path traversal
grep -iE "(\.\.\/|\.\.\\\\|%2e%2e|%252e)" <logfile> | head -20

# Potential webshell access
grep -iE "(cmd=|exec=|shell=|upload.*\.(php|asp|jsp)|eval\(|system\()" <logfile> | head -20

# Large response sizes (data exfiltration)
awk '{print $10, $7, $1}' <logfile> | sort -rn | head -20

# User-Agent analysis
awk -F'"' '{print $6}' <logfile> | sort | uniq -c | sort -rn | head -20
```

**Validation**: For web attacks, confirm:
- Multiple attack patterns from the same IP
- Successful responses (200) after attack attempts indicate exploitation
- Check if suspicious User-Agents correlate with attack IPs

### 4. JSON/Structured Logs

```bash
# Parse with python3 since jq may not be available
python3 -c "
import json, sys
for line in open(sys.argv[1]):
    try:
        obj = json.loads(line.strip())
        print(json.dumps(obj, indent=2))
    except: pass
" <logfile> | head -100
```

### 5. Syslog / General System Logs

```bash
# Cron job analysis (persistence)
grep -i "cron\|crontab\|at " <logfile> | head -30

# Kernel messages (module loading, errors)
grep -iE "kernel:|segfault|oom-killer|module.*loaded" <logfile> | head -30

# Service start/stop anomalies
grep -iE "started|stopped|failed|error" <logfile> | head -50
```

## Correlation Analysis

After initial parsing, correlate across findings:

1. **Timeline**: Sort all suspicious events chronologically to identify attack chains
2. **Source correlation**: Group findings by source IP/user to identify attacker sessions
3. **Lateral movement**: Look for the same credentials used from multiple sources
4. **Privilege escalation**: Authentication events followed by admin actions
5. **Data exfiltration**: Large data transfers after unauthorized access

## Validation Rules

1. **Brute force**: Minimum 5 failed attempts from one source in under 10 minutes
2. **Web attacks**: Attack pattern + successful response code (not just the attempt)
3. **Privilege escalation**: Clear before/after evidence (normal user -> admin action)
4. **Anomalous activity**: Deviation from established baseline (time of day, source, frequency)
5. **Single log entries are NOT findings** — require pattern or corroboration

## Report Output

Write the report to `./reports/log-analysis-report.md`:

```markdown
# Log Analysis Report

**Date**: <date>
**Source**: <log file(s) analyzed>
**Log Type**: <type>
**Time Range**: <earliest to latest entry>
**Analyst**: Claude Code DFIR

## Executive Summary
<Key findings in 2-3 sentences>

## Findings

### Finding 1: <Title>
- **Severity**: Critical / High / Medium / Low / Informational
- **Time Range**: <first occurrence — last occurrence>
- **Evidence**: <specific log entries>
- **Validation**: <how confirmed>
- **MITRE ATT&CK**: <technique ID if applicable>
- **Reproduce**:
  ```bash
  <exact command(s) the analyst can copy-paste to independently verify this finding>
  ```

## Attack Timeline
| Timestamp | Event | Source | Details |
|-----------|-------|--------|---------|

## Indicators of Compromise
| Type | Value | Context |
|------|-------|---------|

## Recommendations
<Numbered response actions>
```

Create the `reports/` directory if it does not exist.
