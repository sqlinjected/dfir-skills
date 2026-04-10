---
name: timeline
description: Build a unified forensic timeline from multiple evidence sources — filesystem MACBtimes, logs, memory artifacts, and network events. Produces a chronological attack narrative.
argument-hint: <path-to-evidence-directory-or-files>
allowed-tools: Bash Read Write Grep Glob
---

# Forensic Timeline Construction

You are building a unified forensic timeline from one or more evidence sources. Merge, normalize, and correlate timestamps from all available sources to reconstruct the sequence of events.

## Target

Evidence path(s): `$ARGUMENTS`

## Pre-flight: Identify Available Evidence

```bash
# List all evidence files
ls -lhR <evidence_path>
file <evidence_path>/*
```

Categorize what is available:
- Disk images (.dd, .raw, .E01, .img)
- Memory dumps (.mem, .raw, .vmem, .dmp)
- PCAP files (.pcap, .pcapng)
- Log files (.log, .evtx, auth.log, syslog, etc.)
- Body files (mactime format)
- Previously generated reports (from other DFIR skills)

## Timeline Construction Procedure

### Step 1: Extract Timestamps from Each Source

#### From Disk Images (Sleuthkit):
```bash
# Generate body file with MAC times
fls -o <offset> -r -m "/" <image> > /tmp/timeline_body.txt

# Convert to sorted timeline
# Body file format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
sort -t'|' -k9 -n /tmp/timeline_body.txt | awk -F'|' '{
  if ($9 > 0) print strftime("%Y-%m-%d %H:%M:%S", $9), "MODIFIED", $2;
  if ($8 > 0) print strftime("%Y-%m-%d %H:%M:%S", $8), "ACCESSED", $2;
  if ($10 > 0) print strftime("%Y-%m-%d %H:%M:%S", $10), "CHANGED", $2;
  if ($11 > 0) print strftime("%Y-%m-%d %H:%M:%S", $11), "CREATED", $2;
}' | sort | head -200
```

#### From Log Files:
```bash
# Extract timestamps from common log formats

# Syslog format (Mon DD HH:MM:SS)
grep -oE "^[A-Z][a-z]{2} [ 0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" <logfile> | head -5

# ISO 8601 format
grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}" <logfile> | head -5

# Apache/Nginx format
grep -oE "\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}" <logfile> | head -5

# Normalize all log entries to: YYYY-MM-DD HH:MM:SS | SOURCE | EVENT
```

#### From PCAPs:
```bash
# Extract packet timestamps
tshark -r <pcap> -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null | head -200
```

#### From Memory Analysis Reports:
```bash
# If previous memory forensics reports exist, extract timestamps from findings
grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" ./reports/memory-forensics-report.md 2>/dev/null
```

#### From Other DFIR Reports:
```bash
# Check for existing reports from other skills
ls ./reports/*.md 2>/dev/null
```

### Step 2: Normalize Timestamps

All timestamps MUST be converted to a single format: `YYYY-MM-DD HH:MM:SS UTC`

Use Python for complex timestamp normalization:
```python
#!/usr/bin/env python3
from datetime import datetime
import re, sys

formats = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]

def normalize(ts_string):
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_string.strip(), fmt)
            # If no year (syslog), assume current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return None
```

### Step 3: Merge into Unified Timeline

Create a unified timeline with this schema:
```
TIMESTAMP | SOURCE | EVENT_TYPE | DETAILS
```

Where:
- **SOURCE**: filesystem, log:<filename>, pcap, memory, report
- **EVENT_TYPE**: file_modified, file_created, logon, logoff, process_start, network_connection, dns_query, etc.

### Step 4: Identify Key Periods

After merging:
1. **Initial access window**: First evidence of malicious activity
2. **Execution window**: Process creation, script execution
3. **Persistence window**: Registry changes, scheduled tasks, new services
4. **Lateral movement window**: Remote connections to other hosts
5. **Exfiltration window**: Large data transfers, unusual outbound connections
6. **Cleanup/covering tracks**: Log deletion, timestomping evidence

### Step 5: Detect Timestomping

Look for indicators:
- Files with creation time AFTER modification time
- Clusters of files with identical timestamps (mass timestomping)
- Filesystem timestamps that don't align with MFT or USN journal

### Step 6: Annotate & Correlate

For each significant event in the timeline:
- Tag it with the relevant MITRE ATT&CK phase (Recon, Initial Access, Execution, Persistence, etc.)
- Cross-reference with other evidence sources
- Note confidence level (High/Medium/Low)

## Validation Rules

1. **Timestamp accuracy**: Verify timezone consistency across sources
2. **Corroboration**: Key events should appear in multiple sources
3. **Logical ordering**: Events must make logical sense in sequence
4. **Gap analysis**: Note significant time gaps that may indicate missing evidence
5. **Timestomping**: Flag if detected but don't discard the evidence

## Report Output

Write the report to `./reports/timeline-report.md`:

```markdown
# Forensic Timeline Report

**Date**: <date>
**Evidence Sources**: <list all sources analyzed>
**Time Range**: <earliest event> to <latest event>
**Timezone**: <UTC or as specified>
**Analyst**: Claude Code DFIR

## Executive Summary
<Attack narrative in 3-5 sentences, covering the full timeline>

## Key Periods
| Phase | Time Range | Description |
|-------|-----------|-------------|
| Initial Access | | |
| Execution | | |
| Persistence | | |
| Lateral Movement | | |
| Exfiltration | | |
| Cleanup | | |

## Unified Timeline

| # | Timestamp | Source | Event Type | Details | ATT&CK Phase | Confidence |
|---|-----------|--------|------------|---------|---------------|------------|
| 1 | | | | | | |

## Anomalies & Gaps
<List any timestomping evidence, unexplained gaps, or conflicting timestamps>

## Attack Narrative
<Prose description of the full attack chain based on the timeline>

## Recommendations
<Numbered response actions based on the timeline>
```

Create the `reports/` directory if it does not exist.
