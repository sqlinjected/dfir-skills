---
name: evidence-acquisition
description: Acquire and preserve digital evidence following forensic best practices. Disk imaging, memory capture, log collection, and chain of custody documentation. Inspired by SIFT workstation methodology.
argument-hint: <device-or-source-path>
allowed-tools: Bash Read Write Grep Glob
---

# Evidence Acquisition & Preservation

You are acquiring digital evidence following forensic best practices. Maintain chain of custody, verify integrity with hashes, and document every step.

**IMPORTANT**: Evidence acquisition may require elevated privileges (sudo). Prompt the user if needed.

## Target

Evidence source: `$ARGUMENTS`

## Pre-flight Checks

```!
which dd 2>/dev/null && echo "dd available"
which dcfldd dc3dd 2>/dev/null || echo "dcfldd/dc3dd not found (dd available as fallback)"
which ewfacquire 2>/dev/null || echo "ewfacquire not found (no E01 support)"
which guymager 2>/dev/null && echo "guymager available (GUI imager)"
which sha256sum md5sum 2>/dev/null || echo "WARNING: hash tools not found"
which photorec testdisk scalpel 2>/dev/null || echo "carving tools status checked"
```

## Acquisition Procedures

### Procedure 1: Disk Imaging (Raw/dd)

```bash
# Identify target device
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
fdisk -l <device> 2>/dev/null

# Create output directory
mkdir -p ./evidence/disk-images

# Acquire with dd (raw format)
# bs=4096 for performance, conv=noerror,sync to handle bad sectors
sudo dd if=<device> of=./evidence/disk-images/<case>-<evidence_id>.dd bs=4096 conv=noerror,sync status=progress

# If dcfldd is available (preferred — built-in hashing and logging)
sudo dcfldd if=<device> of=./evidence/disk-images/<case>-<evidence_id>.dd bs=4096 hash=sha256,md5 hashlog=./evidence/disk-images/<case>-<evidence_id>.hashlog

# If dc3dd is available
sudo dc3dd if=<device> of=./evidence/disk-images/<case>-<evidence_id>.dd hash=sha256 log=./evidence/disk-images/<case>-<evidence_id>.log
```

### Procedure 2: Memory Acquisition (Linux)

```bash
# Method 1: /proc/kcore (requires root)
sudo dd if=/proc/kcore of=./evidence/memory/<case>-memory.raw bs=4096 status=progress

# Method 2: /dev/mem (if available, often restricted)
sudo dd if=/dev/mem of=./evidence/memory/<case>-memory.raw bs=4096 status=progress

# Method 3: LiME module (if available)
# sudo insmod lime.ko "path=./evidence/memory/<case>-memory.lime format=lime"

# Method 4: /proc/meminfo for system context
cat /proc/meminfo > ./evidence/memory/<case>-meminfo.txt
```

### Procedure 3: Live System Triage Collection

Collect volatile data in order of volatility (RFC 3227):

```bash
mkdir -p ./evidence/triage

# 1. Date/time
date -u > ./evidence/triage/datetime.txt

# 2. Running processes
ps auxwwf > ./evidence/triage/processes.txt

# 3. Network connections
ss -tulnp > ./evidence/triage/network-connections.txt
ip addr show > ./evidence/triage/network-interfaces.txt
ip route show > ./evidence/triage/routing-table.txt
ip neigh show > ./evidence/triage/arp-table.txt

# 4. Logged in users
who -a > ./evidence/triage/logged-in-users.txt
last -50 > ./evidence/triage/last-logins.txt
lastlog > ./evidence/triage/lastlog.txt

# 5. Open files
lsof -nP > ./evidence/triage/open-files.txt 2>/dev/null

# 6. Loaded kernel modules
lsmod > ./evidence/triage/kernel-modules.txt

# 7. Mounted filesystems
mount > ./evidence/triage/mounts.txt
df -h > ./evidence/triage/disk-usage.txt

# 8. Scheduled tasks
crontab -l > ./evidence/triage/crontab-current.txt 2>/dev/null
ls -la /etc/cron.* > ./evidence/triage/cron-dirs.txt 2>/dev/null
cat /etc/crontab > ./evidence/triage/etc-crontab.txt 2>/dev/null

# 9. System information
uname -a > ./evidence/triage/system-info.txt
hostname >> ./evidence/triage/system-info.txt
uptime >> ./evidence/triage/system-info.txt

# 10. Environment variables
env > ./evidence/triage/environment.txt

# 11. DNS configuration
cat /etc/resolv.conf > ./evidence/triage/dns-config.txt
cat /etc/hosts > ./evidence/triage/hosts-file.txt

# 12. User accounts
cat /etc/passwd > ./evidence/triage/passwd.txt
cat /etc/shadow > ./evidence/triage/shadow.txt 2>/dev/null
cat /etc/group > ./evidence/triage/group.txt

# 13. SSH artifacts
ls -laR /home/*/.ssh/ > ./evidence/triage/ssh-artifacts.txt 2>/dev/null
cat /home/*/.ssh/authorized_keys > ./evidence/triage/authorized-keys.txt 2>/dev/null
cat /home/*/.ssh/known_hosts > ./evidence/triage/known-hosts.txt 2>/dev/null

# 14. Bash history for all users
for user_home in /home/* /root; do
  if [ -f "$user_home/.bash_history" ]; then
    echo "=== $(basename $user_home) ===" >> ./evidence/triage/bash-histories.txt
    cat "$user_home/.bash_history" >> ./evidence/triage/bash-histories.txt
  fi
done

# 15. Systemd services and timers
systemctl list-units --type=service --all > ./evidence/triage/services.txt 2>/dev/null
systemctl list-timers --all > ./evidence/triage/timers.txt 2>/dev/null
```

### Procedure 4: Log Collection

```bash
mkdir -p ./evidence/logs

# System logs
cp /var/log/syslog ./evidence/logs/ 2>/dev/null
cp /var/log/messages ./evidence/logs/ 2>/dev/null
cp /var/log/auth.log ./evidence/logs/ 2>/dev/null
cp /var/log/secure ./evidence/logs/ 2>/dev/null
cp /var/log/kern.log ./evidence/logs/ 2>/dev/null
cp /var/log/dmesg ./evidence/logs/ 2>/dev/null
cp /var/log/boot.log ./evidence/logs/ 2>/dev/null
cp /var/log/cron ./evidence/logs/ 2>/dev/null

# Web server logs
cp /var/log/apache2/*.log ./evidence/logs/ 2>/dev/null
cp /var/log/nginx/*.log ./evidence/logs/ 2>/dev/null
cp /var/log/httpd/*.log ./evidence/logs/ 2>/dev/null

# Application logs
cp /var/log/mail.log ./evidence/logs/ 2>/dev/null
cp /var/log/dpkg.log ./evidence/logs/ 2>/dev/null
cp /var/log/apt/*.log ./evidence/logs/ 2>/dev/null

# Journald export (systemd)
journalctl --no-pager -o json > ./evidence/logs/journald-full.json 2>/dev/null
```

### Procedure 5: File Carving (Data Recovery)

```bash
mkdir -p ./evidence/carved

# Using scalpel
scalpel -o ./evidence/carved/scalpel-output <image>

# Using photorec (interactive — inform user)
# photorec <image>

# Using bulk_extractor (automated)
bulk_extractor -o ./evidence/carved/be-output <image>
```

### Procedure 6: Integrity Verification

After every acquisition:

```bash
# Hash the acquired evidence
sha256sum ./evidence/**/* > ./evidence/evidence-hashes.sha256
md5sum ./evidence/**/* > ./evidence/evidence-hashes.md5

# Verify (run again to compare)
sha256sum -c ./evidence/evidence-hashes.sha256
```

## Chain of Custody Documentation

After acquisition, generate a chain of custody document:

Write to `./evidence/chain-of-custody.md`:

```markdown
# Chain of Custody Record

## Case Information
| Field | Value |
|-------|-------|
| Case ID | |
| Case Name | |
| Date/Time of Acquisition | <UTC timestamp> |
| Acquiring Analyst | Claude Code DFIR (assisted) |
| Location | |

## Evidence Items

### Item 1
| Field | Value |
|-------|-------|
| Evidence ID | E-001 |
| Description | |
| Source Device/Path | |
| Acquisition Method | |
| Output File | |
| SHA256 | |
| MD5 | |
| File Size | |
| Date/Time Acquired | |

## Custody Log
| Date/Time | Action | Person | Notes |
|-----------|--------|--------|-------|
| | Acquired | | Initial acquisition |

## Notes
- All times in UTC
- Hashes verified immediately after acquisition
- Original evidence was [write-blocked / read-only mounted / not applicable]
```

## Validation Rules

1. **Hash verification**: Every acquired image must have SHA256 and MD5 recorded and verified
2. **Write protection**: Warn if source is not write-blocked (inform user, don't block workflow)
3. **Completeness**: Verify acquired image size matches source device size
4. **Documentation**: Every step must be logged in the chain of custody

## Important Notes

- Always recommend hardware write-blockers for physical media
- For live acquisitions, document that evidence is from a running system and may have changed
- Never mount evidence partitions read-write
- Use `mount -o ro,noexec,nosuid` if mounting evidence for examination
- Inform the user when elevated privileges are required
