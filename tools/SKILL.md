---
name: tools
description: List all available DFIR/SOC skills and installed forensic tools with descriptions and use cases. Quick reference for the analyst.
allowed-tools: Bash Read Glob
---

# DFIR/SOC Toolbox — Quick Reference

Display the available skills and installed tools for the analyst.

## Available Skills (Slash Commands)

Present this table to the user:

| Skill | Command | Description | Primary Use Case |
|-------|---------|-------------|-----------------|
| **Memory Forensics** | `/memory-forensics <dump>` | Analyze RAM dumps with Volatility 3, strings | Detect injected code, hidden processes, network artifacts in memory |
| **Log Analysis** | `/log-analysis <logfile>` | Parse auth.log, syslog, EVTX, web logs, JSON | Detect brute force, lateral movement, priv esc, anomalous logins |
| **Network Forensics** | `/network-forensics <pcap>` | Analyze PCAPs with tshark | Detect C2 beacons, DNS tunneling, data exfil, suspicious traffic |
| **Disk Forensics** | `/disk-forensics <image>` | Analyze disk images with Sleuthkit, binwalk | Recover deleted files, examine artifacts, build filesystem timelines |
| **Malware Triage** | `/malware-triage <file>` | Static analysis of suspicious files | Extract IOCs, analyze PE/ELF structure, assess threat level |
| **Reverse Engineering** | `/reverse-engineering <binary>` | Deep binary analysis with radare2 | Disassemble, analyze control flow, identify capabilities |
| **IOC Extraction** | `/ioc-extract <evidence>` | Extract & classify IOCs from any source | Pull IPs, domains, hashes, URLs from evidence into structured formats |
| **Timeline** | `/timeline <evidence-dir>` | Build unified forensic timeline | Merge filesystem, log, network, and memory timestamps |
| **Alert Triage** | `/alert` | SOC alert investigation guidance | Paste alert + observables for hypotheses and investigation steps |
| **Evidence Acquisition** | `/evidence-acquisition <device>` | Forensic imaging and evidence collection | Disk imaging, memory capture, live triage, chain of custody |
| **DFIR Report** | `/dfir-report [reports-dir]` | Generate comprehensive incident report | Consolidate all findings into executive + technical report |
| **Tools Reference** | `/tools` | This listing — available tools and skills | Quick reference for what's available |

## Installed Tool Inventory

Now check what's actually installed on this system:

```!
echo "=== Core Forensic Tools ==="
echo -n "strings: "; which strings 2>/dev/null || echo "NOT INSTALLED"
echo -n "file: "; which file 2>/dev/null || echo "NOT INSTALLED"
echo -n "xxd: "; which xxd 2>/dev/null || echo "NOT INSTALLED"
echo -n "exiftool: "; which exiftool 2>/dev/null || echo "NOT INSTALLED"
echo -n "binwalk: "; which binwalk 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Hashing ==="
echo -n "sha256sum: "; which sha256sum 2>/dev/null || echo "NOT INSTALLED"
echo -n "md5sum: "; which md5sum 2>/dev/null || echo "NOT INSTALLED"
echo -n "hashdeep: "; which hashdeep 2>/dev/null || echo "NOT INSTALLED"
echo -n "rahash2: "; which rahash2 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Disk Forensics (Sleuthkit) ==="
echo -n "mmls: "; which mmls 2>/dev/null || echo "NOT INSTALLED"
echo -n "fsstat: "; which fsstat 2>/dev/null || echo "NOT INSTALLED"
echo -n "fls: "; which fls 2>/dev/null || echo "NOT INSTALLED"
echo -n "icat: "; which icat 2>/dev/null || echo "NOT INSTALLED"
echo -n "img_stat: "; which img_stat 2>/dev/null || echo "NOT INSTALLED"
echo -n "blkstat: "; which blkstat 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Network Forensics ==="
echo -n "tshark: "; which tshark 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Memory Forensics ==="
echo -n "volatility3: "; which vol 2>/dev/null || python3 -c "import volatility3" 2>/dev/null && echo "python module" || echo "NOT INSTALLED (sudo apt install volatility3)"

echo ""
echo "=== Reverse Engineering ==="
echo -n "radare2: "; which r2 2>/dev/null || echo "NOT INSTALLED"
echo -n "rabin2: "; which rabin2 2>/dev/null || echo "NOT INSTALLED"
echo -n "rasm2: "; which rasm2 2>/dev/null || echo "NOT INSTALLED"
echo -n "rafind2: "; which rafind2 2>/dev/null || echo "NOT INSTALLED"
echo -n "objdump: "; which objdump 2>/dev/null || echo "NOT INSTALLED"
echo -n "readelf: "; which readelf 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Carving & Recovery ==="
echo -n "scalpel: "; which scalpel 2>/dev/null || echo "NOT INSTALLED"
echo -n "photorec: "; which photorec 2>/dev/null || echo "NOT INSTALLED"
echo -n "testdisk: "; which testdisk 2>/dev/null || echo "NOT INSTALLED"
echo -n "bulk_extractor: "; which bulk_extractor 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Document Analysis ==="
echo -n "pdf-parser: "; which pdf-parser 2>/dev/null || echo "NOT INSTALLED"
echo -n "pdfid: "; which pdfid 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Malware / YARA ==="
echo -n "yara: "; which yara 2>/dev/null || echo "NOT INSTALLED (sudo apt install yara)"
echo -n "python3-yara: "; python3 -c "import yara; print('available')" 2>/dev/null || echo "NOT INSTALLED"

echo ""
echo "=== Imaging ==="
echo -n "dd: "; which dd 2>/dev/null || echo "NOT INSTALLED"
echo -n "guymager: "; which guymager 2>/dev/null || echo "NOT INSTALLED (GUI)"
```

Present the tool inventory results to the user in a clean table format showing:
- Tool name
- Status (Installed / Not Installed)
- Install command if missing
- Primary use case

## Missing Tools — Install Commands

If tools are missing, present the user with a single install command:

```
sudo apt install -y volatility3 yara jq foremost ssdeep
```

Adjust the list based on what's actually missing.

## Tool-to-Skill Mapping

| Tool | Used By Skills |
|------|---------------|
| `vol` / `volatility3` | `/memory-forensics` |
| `tshark` | `/network-forensics` |
| `mmls`, `fls`, `icat`, `fsstat` | `/disk-forensics`, `/timeline` |
| `r2`, `rabin2`, `objdump`, `readelf` | `/reverse-engineering`, `/malware-triage` |
| `strings`, `file`, `exiftool` | `/malware-triage`, `/memory-forensics`, `/disk-forensics` |
| `binwalk` | `/malware-triage`, `/disk-forensics` |
| `bulk_extractor` | `/disk-forensics`, `/evidence-acquisition` |
| `scalpel`, `photorec` | `/evidence-acquisition` |
| `yara` | `/malware-triage` |
| `pdf-parser`, `pdfid` | `/reverse-engineering` |
| `sha256sum`, `md5sum`, `hashdeep` | All skills |
| `dd`, `guymager` | `/evidence-acquisition` |
