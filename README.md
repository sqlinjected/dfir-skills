# DFIR/SOC Skills for Claude Code

A comprehensive Digital Forensics & Incident Response (DFIR) and Security Operations Center (SOC) skillset for [Claude Code](https://claude.ai/code). These skills turn Claude Code into a forensic analysis assistant on your Kali Linux workstation.

## Skills

| Skill | Command | Description |
|-------|---------|-------------|
| **Memory Forensics** | `/memory-forensics <dump>` | Analyze RAM dumps with Volatility 3 and strings |
| **Log Analysis** | `/log-analysis <logfile>` | Parse auth.log, syslog, EVTX, Apache/Nginx, JSON logs |
| **Network Forensics** | `/network-forensics <pcap>` | Analyze PCAPs with tshark — C2 beacons, DNS tunneling, exfil |
| **Disk Forensics** | `/disk-forensics <image>` | Sleuthkit analysis — partitions, deleted files, filesystem timelines |
| **Malware Triage** | `/malware-triage <file>` | Static analysis — hashes, strings, PE/ELF headers, YARA |
| **Reverse Engineering** | `/reverse-engineering <binary>` | radare2 deep analysis — disassembly, imports, control flow |
| **IOC Extraction** | `/ioc-extract <evidence>` | Extract IPs, domains, hashes, URLs into MD, CSV, and STIX JSON |
| **Timeline** | `/timeline <evidence-dir>` | Build unified forensic timeline from all evidence sources |
| **Alert Triage** | `/alert` | Paste alert + observables for hypotheses and investigation steps |
| **Evidence Acquisition** | `/evidence-acquisition <device>` | Forensic imaging, memory capture, live triage, chain of custody |
| **DFIR Report** | `/dfir-report [reports-dir]` | Consolidate all findings into executive + technical incident report |
| **Tools Reference** | `/tools` | List all installed tools, skills, and install commands for missing ones |

## Installation

### Quick Install

Copy the skills into your Claude Code personal skills directory:

```bash
mkdir -p ~/.claude/skills
cp -r */ ~/.claude/skills/
```

### Per-Project Install

Copy into a specific project's `.claude/skills/` directory instead:

```bash
mkdir -p /path/to/project/.claude/skills
cp -r */ /path/to/project/.claude/skills/
```

## Required Tools

These skills are designed for **Kali Linux** and leverage the following tools:

| Tool | Install | Used By |
|------|---------|---------|
| Volatility 3 | `pip3 install volatility3 --break-system-packages` | `/memory-forensics` |
| tshark | `sudo apt install tshark` | `/network-forensics` |
| Sleuthkit | `sudo apt install sleuthkit` | `/disk-forensics`, `/timeline` |
| radare2 | `sudo apt install radare2` | `/reverse-engineering`, `/malware-triage` |
| binwalk | `sudo apt install binwalk` | `/malware-triage`, `/disk-forensics` |
| strings, file, exiftool | `sudo apt install binutils file libimage-exiftool-perl` | Multiple |
| bulk_extractor | `sudo apt install bulk-extractor` | `/disk-forensics`, `/evidence-acquisition` |
| yara | `sudo apt install yara` | `/malware-triage` |
| scalpel | `sudo apt install scalpel` | `/evidence-acquisition` |
| pdf-parser, pdfid | `sudo apt install pdfid pdf-parser` | `/reverse-engineering` |

## Key Features

- **Validated Findings**: Every finding includes a `Reproduce` block with exact copy-pasteable bash commands for independent verification
- **Structured Reports**: All skills output to `./reports/` in consistent markdown format
- **MITRE ATT&CK Mapping**: Findings are mapped to ATT&CK technique IDs
- **Cross-Validation**: Findings are corroborated across multiple data sources before reporting
- **Pre-flight Checks**: Skills verify tool availability before running and suggest install commands
- **Multi-Format IOC Output**: IOC extraction produces Markdown, CSV, and STIX-compatible JSON

## Output

All skills write reports to a `./reports/` directory (created automatically). The `/dfir-report` skill consolidates all individual reports into a comprehensive incident report.

## License

MIT
