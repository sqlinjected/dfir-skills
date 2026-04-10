---
name: ioc-extract
description: Extract, deduplicate, and classify Indicators of Compromise (IOCs) from any evidence source — files, logs, memory dumps, PCAPs, reports, or pasted text. Outputs structured IOC lists in multiple formats.
argument-hint: <path-to-evidence-or-paste-text>
allowed-tools: Bash Read Write Grep Glob
---

# IOC Extraction

You are extracting and classifying Indicators of Compromise from evidence. Parse all provided material, extract IOCs, deduplicate, validate, and output in structured formats.

## Target

Evidence source: `$ARGUMENTS`

If no file path is provided, the user may paste raw text containing IOCs directly. In that case, analyze the pasted content.

## Extraction Procedure

### Step 1: Determine Source Type

```bash
file <target> 2>/dev/null || echo "Text input mode — analyzing pasted content"
```

### Step 2: Extract IOCs by Category

#### IPv4 Addresses
```bash
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" <source> | sort -u | while read ip; do
  # Filter out RFC1918 private ranges, localhost, broadcast
  echo "$ip" | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.)" || true
done | sort -u
```

#### IPv6 Addresses
```bash
grep -oiE "([0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}" <source> | sort -u
```

#### Domains
```bash
grep -oiE "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}" <source> | sort -u | grep -viE "\.(png|jpg|gif|css|js|ico|svg|woff)$"
```

#### URLs
```bash
grep -oiE "https?://[^ \"'<>]+" <source> | sort -u
```

#### Email Addresses
```bash
grep -oiE "[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}" <source> | sort -u
```

#### File Hashes
```bash
# MD5
grep -oiE "\b[a-f0-9]{32}\b" <source> | sort -u
# SHA1
grep -oiE "\b[a-f0-9]{40}\b" <source> | sort -u
# SHA256
grep -oiE "\b[a-f0-9]{64}\b" <source> | sort -u
```

#### File Names / Paths
```bash
grep -oiE "[a-z0-9_.-]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|pif|msi|doc[xm]?|xls[xm]?|ppt[xm]?|pdf|jar|py|sh|elf|bin|iso|img|vhd)" <source> | sort -u
```

#### Registry Keys (Windows)
```bash
grep -oiE "HKEY_[A-Z_]+\\\\[^ \"']+" <source> | sort -u
```

#### MITRE ATT&CK Technique IDs
```bash
grep -oE "T[0-9]{4}(\.[0-9]{3})?" <source> | sort -u
```

#### CVE IDs
```bash
grep -oiE "CVE-[0-9]{4}-[0-9]{4,}" <source> | sort -u
```

#### User Agents
```bash
grep -oiE "Mozilla/[^ ]+ \([^)]+\)[^\"]*" <source> | sort -u | head -20
```

#### JA3/JA3S Hashes
```bash
# These are MD5-length but in specific context
grep -oiE "ja3[s]?=[a-f0-9]{32}" <source> | sort -u
```

### Step 3: Validation & Deduplication

For each extracted IOC category:

1. **Deduplicate**: Remove exact duplicates
2. **Defang check**: Handle defanged IOCs (e.g., `hxxp://`, `[.]com`, `[:]80`)
   ```bash
   # Re-fang common defanging patterns for analysis
   sed -e 's/hxxp/http/gi' -e 's/\[.\]/./g' -e 's/\[:\]/:/g' -e 's/ dot /./gi'
   ```
3. **False positive filtering**:
   - Remove private/reserved IPs (10.x, 172.16-31.x, 192.168.x, 127.x)
   - Remove common benign domains (microsoft.com, google.com, etc.) — unless contextually relevant
   - Remove hash-like strings that are clearly not hashes (e.g., CSS color codes in context)
4. **Validate format**: Ensure IPs have valid octets (0-255), domains have valid TLD, hashes are correct length

### Step 4: Enrichment (if possible)

For high-priority IOCs, note context:
- Where in the evidence was this IOC found?
- How many times does it appear?
- Is it associated with a specific process, user, or timeframe?

## Output Formats

### Format 1: Structured Report (default)

Write to `./reports/ioc-extract-report.md`:

```markdown
# IOC Extraction Report

**Date**: <date>
**Source**: <evidence source>
**Analyst**: Claude Code DFIR

## Summary
- **Total unique IOCs**: <count>
- **Categories**: <list>

## IOCs by Category

### Network Indicators
#### IP Addresses (<count>)
| IP | Occurrences | Context |
|----|-------------|---------|

#### Domains (<count>)
| Domain | Occurrences | Context |
|--------|-------------|---------|

#### URLs (<count>)
| URL | Context |
|-----|---------|

### Host Indicators
#### File Hashes
| Hash Type | Hash | Associated Filename |
|-----------|------|---------------------|

#### File Names
| Filename | Context |
|----------|---------|

#### Registry Keys
| Key | Context |
|-----|---------|

### Email Addresses
| Email | Context |
|-------|---------|

### Threat Intel References
| CVE | MITRE ATT&CK | Context |
|-----|---------------|---------|
```

### Format 2: CSV (for SIEM import)

Also write to `./reports/iocs.csv`:
```
type,value,context,source
```

### Format 3: STIX-compatible JSON (simplified)

Also write to `./reports/iocs.json`:
```json
{
  "type": "bundle",
  "objects": [
    {
      "type": "indicator",
      "pattern": "[ipv4-addr:value = 'x.x.x.x']",
      "valid_from": "<date>",
      "description": "<context>"
    }
  ]
}
```

Create the `reports/` directory if it does not exist. Generate all three output formats.
