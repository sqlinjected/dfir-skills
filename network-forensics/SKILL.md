---
name: network-forensics
description: Analyze PCAP/PCAPNG network captures using tshark. Detect C2 beacons, data exfiltration, lateral movement, DNS tunneling, and suspicious traffic patterns.
argument-hint: <path-to-pcap-file>
allowed-tools: Bash Read Write Grep Glob
---

# Network Forensics Analysis

You are performing network forensics on a packet capture file. Systematically analyze traffic patterns, extract IOCs, and identify malicious activity.

## Target

PCAP file: `$ARGUMENTS`

## Pre-flight Checks

```!
which tshark 2>/dev/null && echo "tshark available: $(tshark --version 2>&1 | head -1)" || echo "WARNING: tshark not found. Install with: sudo apt install tshark -y"
```

## Analysis Procedure

### Phase 1: Capture Overview

```bash
# Capture file statistics
tshark -r <pcap> -q -z io,stat,0

# Protocol hierarchy
tshark -r <pcap> -q -z io,phs

# Capture duration and packet count
tshark -r <pcap> -q -z conv,ip | head -30

# Endpoints summary
tshark -r <pcap> -q -z endpoints,ip | head -30
```

### Phase 2: Conversation Analysis

```bash
# Top TCP conversations by bytes
tshark -r <pcap> -q -z conv,tcp | sort -t'|' -k5 -rn | head -20

# Top UDP conversations
tshark -r <pcap> -q -z conv,udp | head -20

# Identify top talkers
tshark -r <pcap> -T fields -e ip.src -e ip.dst -e frame.len | sort | head -1000 | awk '{a[$1]+=$3; b[$2]+=$3} END {for(i in a) print a[i], "bytes sent by", i; for(i in b) print b[i], "bytes received by", i}' | sort -rn | head -20
```

### Phase 3: DNS Analysis

```bash
# All DNS queries
tshark -r <pcap> -Y "dns.qr==0" -T fields -e frame.time -e ip.src -e dns.qry.name | sort -k3 | head -100

# DNS query frequency (beaconing / tunneling detection)
tshark -r <pcap> -Y "dns.qr==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -30

# Long DNS names (potential DNS tunneling)
tshark -r <pcap> -Y "dns.qr==0" -T fields -e dns.qry.name | awk 'length > 50' | head -20

# TXT record queries (C2 / data exfil channel)
tshark -r <pcap> -Y "dns.qry.type==16" -T fields -e frame.time -e ip.src -e dns.qry.name | head -30

# DNS responses with unusual TTLs
tshark -r <pcap> -Y "dns.qr==1" -T fields -e dns.qry.name -e dns.a -e dns.resp.ttl | sort -u | head -30
```

**Validation for DNS tunneling**:
- Average query name length > 50 characters
- High volume of queries to a single domain
- TXT record queries with encoded data in responses
- Subdomain entropy analysis (random-looking subdomains)

### Phase 4: HTTP/HTTPS Analysis

```bash
# HTTP requests
tshark -r <pcap> -Y "http.request" -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.host -e http.request.uri -e http.user_agent | head -50

# HTTP responses with status codes
tshark -r <pcap> -Y "http.response" -T fields -e frame.time -e ip.src -e http.response.code -e http.content_type | head -50

# HTTP POST requests (data exfiltration)
tshark -r <pcap> -Y "http.request.method==POST" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.content_length | head -30

# Suspicious User-Agents
tshark -r <pcap> -Y "http.user_agent" -T fields -e http.user_agent | sort | uniq -c | sort -rn | head -20

# TLS/SSL: Extract SNI (Server Name Indication) for HTTPS
tshark -r <pcap> -Y "tls.handshake.extensions_server_name" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name | sort -u | head -50

# JA3 fingerprints (if supported)
tshark -r <pcap> -Y "tls.handshake.type==1" -T fields -e ip.src -e tls.handshake.ja3 2>/dev/null | sort | uniq -c | sort -rn | head -20
```

### Phase 5: Suspicious Traffic Patterns

```bash
# Beaconing detection: regular interval connections to same dest
tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport | head -500

# Unusual ports
tshark -r <pcap> -Y "tcp.dstport > 1024" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head -30

# ICMP traffic (potential covert channel or tunneling)
tshark -r <pcap> -Y "icmp" -T fields -e frame.time -e ip.src -e ip.dst -e data.len | head -30

# SMB/CIFS traffic (lateral movement)
tshark -r <pcap> -Y "smb || smb2" -T fields -e frame.time -e ip.src -e ip.dst -e smb2.cmd -e smb2.filename 2>/dev/null | head -30

# Kerberos traffic
tshark -r <pcap> -Y "kerberos" -T fields -e frame.time -e ip.src -e ip.dst -e kerberos.CNameString 2>/dev/null | head -30

# RDP traffic
tshark -r <pcap> -Y "tcp.port==3389" -T fields -e frame.time -e ip.src -e ip.dst | sort -u | head -20
```

### Phase 6: Beaconing Analysis (Python)

For suspected beaconing, calculate inter-arrival times:

```python
#!/usr/bin/env python3
import subprocess, sys, statistics

result = subprocess.run(
    ['tshark', '-r', sys.argv[1], '-Y', f'ip.dst=={sys.argv[2]}',
     '-T', 'fields', '-e', 'frame.time_epoch'],
    capture_output=True, text=True
)
times = [float(t) for t in result.stdout.strip().split('\n') if t]
if len(times) > 2:
    deltas = [times[i+1]-times[i] for i in range(len(times)-1)]
    print(f"Connections: {len(times)}")
    print(f"Mean interval: {statistics.mean(deltas):.2f}s")
    print(f"Std deviation: {statistics.stdev(deltas):.2f}s")
    print(f"Jitter ratio: {statistics.stdev(deltas)/statistics.mean(deltas):.4f}")
    if statistics.stdev(deltas)/statistics.mean(deltas) < 0.15:
        print("HIGH CONFIDENCE: Regular beaconing detected")
    elif statistics.stdev(deltas)/statistics.mean(deltas) < 0.30:
        print("MEDIUM CONFIDENCE: Possible beaconing with jitter")
```

### Phase 7: File Extraction

```bash
# Extract HTTP objects
mkdir -p /tmp/pcap_exports
tshark -r <pcap> --export-objects http,/tmp/pcap_exports/ 2>/dev/null
ls -la /tmp/pcap_exports/ 2>/dev/null | head -20

# Extract SMB objects
tshark -r <pcap> --export-objects smb,/tmp/pcap_exports/ 2>/dev/null

# Hash any extracted files
sha256sum /tmp/pcap_exports/* 2>/dev/null | head -20
```

## Validation Rules

1. **C2 beaconing**: Requires regular intervals (jitter ratio < 0.3) over sustained period
2. **DNS tunneling**: Requires both high volume AND long/encoded query names to same domain
3. **Data exfiltration**: Large outbound transfers confirmed by content type and destination
4. **Lateral movement**: SMB/RDP/WinRM to internal IPs confirmed by authentication events
5. **Single packets are NOT findings** — require patterns or corroboration

## Report Output

Write the report to `./reports/network-forensics-report.md`:

```markdown
# Network Forensics Report

**Date**: <date>
**PCAP File**: <filename>
**Capture Duration**: <start — end>
**Total Packets**: <count>
**Analyst**: Claude Code DFIR

## Executive Summary
<Key findings in 2-3 sentences>

## Findings

### Finding 1: <Title>
- **Severity**: Critical / High / Medium / Low / Informational
- **Traffic Pattern**: <description>
- **Source -> Destination**: <IPs and ports>
- **Evidence**: <specific tshark output>
- **Validation**: <how confirmed>
- **MITRE ATT&CK**: <technique ID>
- **Reproduce**:
  ```bash
  <exact tshark/command(s) the analyst can copy-paste to independently verify this finding>
  ```

## Network IOCs
| Type | Value | Context |
|------|-------|---------|
| IP   |       |         |
| Domain |     |         |
| Port |       |         |
| JA3  |       |         |
| User-Agent | |        |

## Traffic Timeline
| Timestamp | Source | Destination | Protocol | Details |
|-----------|--------|-------------|----------|---------|

## Recommendations
<Numbered response actions>
```

Create the `reports/` directory if it does not exist.
