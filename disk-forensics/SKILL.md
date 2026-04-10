---
name: disk-forensics
description: Analyze disk images and filesystem artifacts using Sleuthkit (mmls, fls, icat), binwalk, strings, and bulk_extractor. Recover deleted files, build timelines, and examine partition structures.
argument-hint: <path-to-disk-image>
allowed-tools: Bash Read Write Grep Glob
---

# Disk Forensics Analysis

You are performing disk forensics on a disk image. Systematically analyze the filesystem, recover artifacts, and identify evidence of malicious activity.

## Target

Disk image: `$ARGUMENTS`

## Pre-flight Checks

```!
which mmls fls icat fsstat img_stat 2>/dev/null || echo "WARNING: Sleuthkit not found. Install with: sudo apt install sleuthkit -y"
which binwalk 2>/dev/null || echo "WARNING: binwalk not found"
which bulk_extractor 2>/dev/null || echo "WARNING: bulk_extractor not found"
which strings exiftool 2>/dev/null || echo "WARNING: strings/exiftool not found"
```

## Analysis Procedure

### Phase 1: Image Identification

```bash
# Image metadata
img_stat <image>

# File type identification
file <image>

# Partition layout
mmls <image>
```

Note the partition offsets from `mmls` output — you will need these (in sectors) for subsequent commands. The offset for the main data partition is typically the largest one.

### Phase 2: Filesystem Analysis

For each relevant partition (use the sector offset from mmls):

```bash
# Filesystem details
fsstat -o <offset> <image>

# Root directory listing
fls -o <offset> <image>

# Full recursive file listing with timestamps (mactime format)
fls -o <offset> -r -m "/" <image> > /tmp/bodyfile.txt
head -50 /tmp/bodyfile.txt
```

### Phase 3: Deleted File Recovery

```bash
# List deleted files (entries marked with *)
fls -o <offset> -r -d <image> | head -50

# To recover a specific deleted file by inode number:
# icat -o <offset> <image> <inode> > /tmp/recovered_file
```

**Validation**: After recovery, verify file integrity:
```bash
file /tmp/recovered_file
sha256sum /tmp/recovered_file
```

### Phase 4: Timeline Analysis

```bash
# Create body file for mactime analysis
fls -o <offset> -r -m "/" <image> > /tmp/bodyfile.txt

# Sort by modification time to find recently changed files
sort -t'|' -k9 /tmp/bodyfile.txt | tail -50

# Look for files modified in a suspicious timeframe
# (adjust dates based on incident timeline)
grep -E "suspicious_date_pattern" /tmp/bodyfile.txt
```

### Phase 5: Artifact Analysis

#### User artifacts (if Windows NTFS):
```bash
# Look for common artifact locations
fls -o <offset> -r <image> | grep -iE "ntuser\.dat|usrclass\.dat|prefetch|recent|amcache"

# Browser artifacts
fls -o <offset> -r <image> | grep -iE "history|cookies|cache|downloads|places\.sqlite"

# Event logs
fls -o <offset> -r <image> | grep -iE "\.evtx$"

# Startup/persistence locations
fls -o <offset> -r <image> | grep -iE "startup|run|runonce|tasks"
```

#### User artifacts (if Linux ext):
```bash
fls -o <offset> -r <image> | grep -iE "bash_history|\.ssh|crontab|authorized_keys|\.profile|\.bashrc|/var/log/"
```

### Phase 6: Keyword Searching

```bash
# Search raw image for strings
strings -a -t d <image> | grep -iE "(password|secret|key|token|hack|exploit|shell)" | head -50

# Search for IPs and URLs
strings -a -n 8 <image> | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u | head -30
strings -a -n 8 <image> | grep -oiE "https?://[^ \"'>]+" | sort -u | head -30

# Search for email addresses
strings -a -n 8 <image> | grep -oiE "[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}" | sort -u | head -30
```

### Phase 7: Embedded File Detection

```bash
# Scan for embedded files and signatures
binwalk -B <image> | head -50

# If specific carved files are needed
# binwalk -e --directory /tmp/binwalk_output <image>
```

### Phase 8: Bulk Extractor (Automated Artifact Extraction)

```bash
# Run bulk_extractor for automated artifact carving
mkdir -p /tmp/be_output
bulk_extractor -o /tmp/be_output -e net -e email -e url <image>

# Review results
cat /tmp/be_output/url.txt 2>/dev/null | head -30
cat /tmp/be_output/email.txt 2>/dev/null | head -30
cat /tmp/be_output/domain.txt 2>/dev/null | head -30
```

### Phase 9: Hash Analysis

```bash
# Hash the entire image for integrity
sha256sum <image>
md5sum <image>

# Hash individual recovered files
sha256sum /tmp/recovered_* 2>/dev/null
```

## Validation Rules

1. **Deleted files**: Recovery confirmed by valid file header and content
2. **Timeline events**: Corroborate filesystem timestamps with log entries when available
3. **Keyword hits**: Raw string hits must be contextualized (which file/partition, surrounding data)
4. **Carved files**: Validate with `file` command — not every binwalk signature is a real file
5. **Partition anomalies**: Compare expected vs actual partition sizes for hidden volumes

## Report Output

Write the report to `./reports/disk-forensics-report.md`:

```markdown
# Disk Forensics Report

**Date**: <date>
**Image**: <filename>
**Image Hash (SHA256)**: <hash>
**Filesystem(s)**: <detected types>
**Analyst**: Claude Code DFIR

## Executive Summary
<Key findings in 2-3 sentences>

## Partition Layout
| # | Start | End | Size | Type | Description |
|---|-------|-----|------|------|-------------|

## Findings

### Finding 1: <Title>
- **Severity**: Critical / High / Medium / Low / Informational
- **Location**: <partition, path, offset>
- **Evidence**: <specific data>
- **Validation**: <how confirmed>
- **MITRE ATT&CK**: <technique ID if applicable>
- **Reproduce**:
  ```bash
  <exact command(s) the analyst can copy-paste to independently verify this finding>
  ```

## Recovered Files
| Filename | Inode | SHA256 | Type | Significance |
|----------|-------|--------|------|-------------|

## Indicators of Compromise
| Type | Value | Context |
|------|-------|---------|

## Timeline of Significant Events
| Timestamp | Event | File/Path | Details |
|-----------|-------|-----------|---------|

## Recommendations
<Numbered response actions>
```

Create the `reports/` directory if it does not exist.
