---
name: dfir-report
description: Generate a comprehensive DFIR incident report by consolidating findings from all analysis skills (memory, disk, network, log, malware, IOCs, timeline). Produces an executive and technical report.
argument-hint: [path-to-reports-directory or leave empty for ./reports/]
allowed-tools: Bash Read Write Grep Glob
---

# DFIR Incident Report Generator

You are consolidating all forensic findings into a final incident report. Read all available analysis reports, cross-reference findings, and produce a comprehensive document suitable for both executive and technical audiences.

## Input

Reports directory: `$ARGUMENTS`

If no argument is provided, default to `./reports/`.

## Procedure

### Step 1: Collect All Available Reports

```bash
ls -la ./reports/*.md 2>/dev/null || echo "No reports found in ./reports/"
ls -la <provided_path>/*.md 2>/dev/null
```

Read every available report file:
- `memory-forensics-report.md`
- `log-analysis-report.md`
- `network-forensics-report.md`
- `disk-forensics-report.md`
- `malware-triage-report.md`
- `ioc-extract-report.md`
- `timeline-report.md`
- `alert-triage-*.md`
- Any other `.md` reports in the directory

### Step 2: Cross-Reference & Correlate

For every finding across all reports:
1. **Identify overlapping IOCs** — same IP, hash, or domain appearing in multiple reports strengthens confidence
2. **Build the attack chain** — connect findings into a coherent narrative (initial access -> execution -> persistence -> lateral movement -> exfiltration)
3. **Resolve conflicts** — if reports disagree on timestamps or details, note the discrepancy and determine the most reliable source
4. **Validate completeness** — identify gaps in the investigation

### Step 3: Determine Incident Severity

Based on consolidated findings:

| Severity | Criteria |
|----------|----------|
| **Critical** | Active data breach, ransomware deployment, domain compromise |
| **High** | Confirmed malware execution, credential theft, lateral movement |
| **Medium** | Successful initial access, persistence established, no confirmed impact |
| **Low** | Blocked attack, failed exploitation, reconnaissance only |

### Step 4: Generate Report

Write the final report to `./reports/DFIR-INCIDENT-REPORT.md`:

```markdown
# DFIR Incident Report

---
**Classification**: CONFIDENTIAL
**Report Date**: <date>
**Incident ID**: IR-<YYYYMMDD>-001
**Analyst**: Claude Code DFIR
**Status**: Draft / Final
---

## 1. Executive Summary

<3-5 paragraph high-level summary written for non-technical stakeholders. Cover:>
- What happened
- When it happened (timeframe)
- What was impacted (systems, data, users)
- Current containment status
- Key recommendations

**Incident Severity**: CRITICAL / HIGH / MEDIUM / LOW

## 2. Incident Overview

| Field | Details |
|-------|---------|
| Incident Type | <malware, breach, insider threat, etc.> |
| Detection Date | |
| Incident Start (estimated) | |
| Incident End | |
| Affected Systems | |
| Affected Users | |
| Data Impact | |
| MITRE ATT&CK Tactics | |

## 3. Attack Narrative

<Chronological prose description of the entire incident from initial access through detection. Reference specific evidence.>

### 3.1 Initial Access
<How the attacker gained entry>

### 3.2 Execution
<What the attacker ran>

### 3.3 Persistence
<How the attacker maintained access>

### 3.4 Privilege Escalation
<How the attacker elevated permissions>

### 3.5 Lateral Movement
<How the attacker moved through the network>

### 3.6 Collection & Exfiltration
<What data was accessed or stolen>

### 3.7 Impact
<Damage assessment>

## 4. Technical Findings

Each finding below includes a **Reproduce** block with exact commands the analyst can run to independently verify.

### 4.1 Memory Forensics
<Consolidated findings from memory analysis, if available. Preserve Reproduce blocks from source reports.>

### 4.2 Disk Forensics
<Consolidated findings from disk analysis, if available. Preserve Reproduce blocks from source reports.>

### 4.3 Network Forensics
<Consolidated findings from network analysis, if available. Preserve Reproduce blocks from source reports.>

### 4.4 Log Analysis
<Consolidated findings from log analysis, if available. Preserve Reproduce blocks from source reports.>

### 4.5 Malware Analysis
<Consolidated findings from malware triage, if available. Preserve Reproduce blocks from source reports.>

## 5. Indicators of Compromise

### 5.1 Network Indicators
| Type | Value | Context | First Seen | Confidence |
|------|-------|---------|------------|------------|

### 5.2 Host Indicators
| Type | Value | Context | First Seen | Confidence |
|------|-------|---------|------------|------------|

### 5.3 Email Indicators
| Type | Value | Context |
|------|-------|---------|

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| Initial Access | | | |
| Execution | | | |
| Persistence | | | |
| Privilege Escalation | | | |
| Defense Evasion | | | |
| Credential Access | | | |
| Discovery | | | |
| Lateral Movement | | | |
| Collection | | | |
| Exfiltration | | | |
| Impact | | | |

## 7. Timeline of Events

| # | Timestamp (UTC) | Event | Source | Details |
|---|-----------------|-------|--------|---------|

## 8. Affected Assets

| Hostname/IP | Role | Impact | Status |
|-------------|------|--------|--------|

## 9. Recommendations

### 9.1 Immediate Actions (0-24 hours)
1. <Containment steps>

### 9.2 Short-term Actions (1-7 days)
1. <Eradication and recovery steps>

### 9.3 Long-term Actions (1-3 months)
1. <Hardening and prevention steps>

## 10. Lessons Learned

### 10.1 What Worked
- <Effective detections/responses>

### 10.2 What Needs Improvement
- <Gaps identified>

### 10.3 Detection Improvements
| Current Gap | Recommended Detection | Priority |
|-------------|----------------------|----------|

## 11. Evidence Inventory

| # | Evidence Type | Filename | SHA256 | Collected By | Date |
|---|--------------|----------|--------|-------------|------|

## 12. Appendices

### Appendix A: Raw IOC List
<Complete deduplicated IOC list for blocklist import>

### Appendix B: Source Reports
<List of all individual analysis reports referenced>

---
**Report prepared by**: Claude Code DFIR
**Review status**: Requires human review and approval before distribution
**Distribution**: <To be determined by incident commander>
```

## Important Notes

- This report is a DRAFT that requires human review before distribution
- Clearly mark any assumptions or uncertainties
- Do not overstate confidence in findings
- Preserve chain of custody references
- If sections have no available data, mark them as "No evidence analyzed" rather than removing them
- The executive summary must be understandable by non-technical management

Create the `reports/` directory if it does not exist.
