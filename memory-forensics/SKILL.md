---
name: memory-forensics
description: Analyze memory dumps using Volatility 3 and strings. Enumerate processes, network connections, injected code, and suspicious artifacts from RAM captures.
argument-hint: <path-to-memory-dump>
allowed-tools: Bash Read Write Grep Glob
---

# Memory Forensics Analysis

You are performing memory forensics on a RAM dump. Your goal is to systematically analyze the memory image, validate every finding, and produce a structured report.

## Target

Memory dump path: `$ARGUMENTS`

## Pre-flight Checks

Before starting, verify tool availability:

```!
which vol 2>/dev/null && echo "vol available at $(which vol)" || echo "WARNING: Volatility 3 not found. Install with: pip3 install volatility3 --break-system-packages"
which strings 2>/dev/null || echo "WARNING: strings not found"
```

If Volatility 3 is not installed, inform the user and offer to install it (`pip3 install volatility3 --break-system-packages`). You can still perform strings-based analysis while waiting.

## Analysis Procedure

Work through each phase sequentially. For each finding, **validate it** by cross-referencing with at least one other data source or plugin before reporting it.

### Phase 1: Image Identification

Determine the OS profile/layer:
```
vol -f <image> banners.Banners
vol -f <image> windows.info.Info
vol -f <image> linux.bash.Bash
```
Use whichever OS applies. If `vol` is not available, try `python3 -m volatility3`.

### Phase 2: Process Analysis

List and analyze processes:
```
vol -f <image> windows.pslist.PsList
vol -f <image> windows.pstree.PsTree
vol -f <image> windows.psscan.PsScan
```

**Validation**: Compare PsList vs PsScan output. Processes found by PsScan but NOT in PsList may indicate hidden/unlinked processes (rootkit behavior). Flag these.

Look for suspicious indicators:
- Processes with unusual parent-child relationships (e.g., cmd.exe spawned by iexplore.exe)
- Misspelled system process names (e.g., `scvhost.exe` instead of `svchost.exe`)
- System processes running from wrong paths
- Processes with abnormal PID/PPID relationships

### Phase 3: Network Connections

```
vol -f <image> windows.netstat.NetStat
vol -f <image> windows.netscan.NetScan
```

**Validation**: Cross-reference connection PIDs with the process list from Phase 2. Flag:
- Connections to known-bad ports (4444, 5555, 1337, 8080 from non-web processes)
- Connections from processes that should not be network-active (notepad.exe, calc.exe)
- Listening ports on unusual interfaces

### Phase 4: Code Injection Detection

```
vol -f <image> windows.malfind.Malfind
vol -f <image> windows.hollowprocesses.HollowProcesses
```

**Validation**: For any malfind hits, check the flagged memory region:
- Does it contain MZ headers (PE injection)?
- Is the process legitimate but with injected code?
- Cross-reference with process analysis from Phase 2

### Phase 5: Persistence & Loaded Modules

```
vol -f <image> windows.registry.hivelist.HiveList
vol -f <image> windows.svcscan.SvcScan
vol -f <image> windows.dlllist.DllList --pid <suspicious_pid>
vol -f <image> windows.modules.Modules
vol -f <image> windows.driverscan.DriverScan
```

Look for:
- Suspicious services (unusual binary paths, misspelled names)
- DLLs loaded from temp directories or user-writable paths
- Unsigned or anomalous kernel drivers

### Phase 6: Credential & Sensitive Data Extraction

```
vol -f <image> windows.hashdump.Hashdump
vol -f <image> windows.lsadump.Lsadump
vol -f <image> windows.cachedump.Cachedump
```

### Phase 7: Strings Analysis (Supplementary)

Use strings as a supplementary technique:
```
strings -a -n 8 <image> | grep -iE "(http[s]?://|ftp://|\\\\\\\\[0-9])" | sort -u | head -100
strings -a -n 8 <image> | grep -iE "(password|passwd|credential|token|api.key)" | sort -u | head -50
strings -a -n 8 <image> | grep -iE "([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+" | sort -u | head -50
```

### Phase 8: Linux Memory (if applicable)

If the image is a Linux memory dump:
```
vol -f <image> linux.pslist.PsList
vol -f <image> linux.pstree.PsTree
vol -f <image> linux.bash.Bash
vol -f <image> linux.check_syscall.Check_syscall
vol -f <image> linux.check_modules.Check_modules
vol -f <image> linux.tty_check.tty_check
vol -f <image> linux.sockstat.Sockstat
```

## Validation Rules

Every finding MUST be validated before inclusion in the report:
1. **Process anomalies**: Confirmed by at least two plugins (e.g., pslist + psscan, or pslist + netscan)
2. **Network IOCs**: IP/port confirmed in both netscan output AND associated with a suspicious process
3. **Injection**: Malfind hit confirmed by examining the actual memory content (MZ headers, shellcode patterns)
4. **Strings hits**: Corroborated by a process or network finding — raw strings alone are insufficient for a finding

## Report Output

After analysis, write a report to `./reports/memory-forensics-report.md` using this structure:

```markdown
# Memory Forensics Report

**Date**: <date>
**Image**: <filename>
**OS Profile**: <detected profile>
**Analyst**: Claude Code DFIR

## Executive Summary
<2-3 sentence overview of key findings>

## Findings

### Finding 1: <Title>
- **Severity**: Critical / High / Medium / Low / Informational
- **Evidence**: <specific data from plugins>
- **Validation**: <how this was cross-referenced>
- **MITRE ATT&CK**: <technique ID if applicable>
- **Reproduce**:
  ```bash
  <exact command(s) the analyst can copy-paste to independently verify this finding>
  ```

### Finding 2: ...

## Indicators of Compromise
| Type | Value | Context |
|------|-------|---------|
| IP   |       |         |
| Domain |     |         |
| Hash |       |         |
| Process |    |         |

## Recommendations
<Numbered list of response actions>

## Raw Evidence Appendix
<Key command outputs preserved for chain of custody>
```

Create the `reports/` directory if it does not exist.
