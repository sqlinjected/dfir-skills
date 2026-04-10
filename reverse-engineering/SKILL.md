---
name: reverse-engineering
description: Reverse engineer binaries using radare2 (r2), rabin2, objdump, readelf, and strings. Analyze PE/ELF executables, shellcode, scripts, and documents. Covers disassembly, control flow, imports, crypto detection, and anti-analysis techniques.
argument-hint: <path-to-binary>
allowed-tools: Bash Read Write Grep Glob
---

# Reverse Engineering Analysis

You are reverse engineering a binary or suspicious file using radare2 and supporting tools. Systematically analyze the target, document functionality, and identify malicious behavior.

**SAFETY**: Do NOT execute the binary. Analysis is static only unless the user explicitly requests dynamic/debug analysis.

## Target

Binary: `$ARGUMENTS`

## Pre-flight Checks

```!
which r2 rabin2 rahash2 rafind2 rasm2 rax2 2>/dev/null || echo "WARNING: radare2 suite not found"
which objdump readelf strings file 2>/dev/null || echo "WARNING: binutils not found"
which pdf-parser pdfid 2>/dev/null || echo "pdf tools available"
```

## Analysis Procedure

### Phase 1: File Identification & Hashing

```bash
# File type
file <target>

# Hashes
sha256sum <target>
md5sum <target>

# Radare2 hashing (multiple algorithms)
rahash2 -a md5,sha1,sha256,crc32 <target>

# File size
ls -lh <target>
```

### Phase 2: Binary Metadata (rabin2)

rabin2 is the radare2 binary info extractor — use it for fast metadata without loading the full r2 shell.

```bash
# General binary info (arch, bits, OS, format, endianness)
rabin2 -I <target>

# Entry points
rabin2 -e <target>

# Imports (external API calls)
rabin2 -i <target>

# Exports
rabin2 -E <target>

# Symbols
rabin2 -s <target>

# Strings (with minimum length 6)
rabin2 -z <target> | head -100

# Wide strings
rabin2 -zz <target> | head -100

# Sections
rabin2 -S <target>

# Libraries/dependencies
rabin2 -l <target>

# Relocations
rabin2 -R <target> | head -50

# Header fields
rabin2 -H <target>

# Class info (for C++/Java/ObjC binaries)
rabin2 -c <target> 2>/dev/null | head -30
```

### Phase 3: ELF-Specific Analysis (Linux binaries)

```bash
# ELF header
readelf -h <target>

# Section headers with flags
readelf -S <target>

# Program headers (segments)
readelf -l <target>

# Dynamic section
readelf -d <target>

# Symbol table
readelf -s <target> | head -50

# Notes section
readelf -n <target>

# Check for RELRO, stack canary, NX, PIE
readelf -l <target> | grep -i "GNU_RELRO"
readelf -s <target> | grep -i "__stack_chk_fail"
readelf -l <target> | grep -i "GNU_STACK"
rabin2 -I <target> | grep -iE "pic|canary|nx|relro"
```

### Phase 4: PE-Specific Analysis (Windows binaries)

```bash
# PE header info
objdump -x <target> | head -100

# PE sections
objdump -h <target>

# DLL imports
objdump -p <target> | grep -A2000 "Import Tables" | head -200

# Check for suspicious section names
objdump -h <target> | awk '{print $2}' | grep -viE "^(\.text|\.data|\.rdata|\.rsrc|\.reloc|\.bss|\.idata|\.edata|$)" | head -20

# Compilation timestamp
rabin2 -I <target> | grep -i "compiled\|timestamp\|date"

# Check for TLS callbacks (anti-debug)
objdump -p <target> | grep -i "TLS"
```

### Phase 5: Radare2 Deep Analysis

```bash
# Quick analysis - function detection
r2 -q -c "aaa" <target> 2>/dev/null

# List all detected functions (sorted by size)
r2 -q -c "aaa; afl~[2,0,3]" <target> | sort -rn | head -40

# Function count
r2 -q -c "aaa; afl~?" <target>

# Entry point disassembly (first 50 instructions)
r2 -q -c "aaa; s entry0; pd 50" <target>

# Main function (if detected)
r2 -q -c "aaa; s main; pdf" <target> 2>/dev/null

# Cross-references to imports (what calls what)
r2 -q -c "aaa; axt @@ sym.imp.*" <target> 2>/dev/null | head -50

# String cross-references (what code references which strings)
r2 -q -c "aaa; axt @@ str.*" <target> 2>/dev/null | head -50
```

### Phase 6: Suspicious Import Analysis

Categorize imports by threat behavior:

```bash
# Process injection
r2 -q -c "aaa; afl" <target> 2>/dev/null | grep -iE "VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|QueueUserAPC|NtQueueApcThread"

# Code execution
r2 -q -c "aaa; afl" <target> 2>/dev/null | grep -iE "WinExec|ShellExecute|CreateProcess|system|exec|popen"

# File operations
rabin2 -i <target> | grep -iE "CreateFile|WriteFile|ReadFile|DeleteFile|MoveFile|CopyFile|fopen|fwrite"

# Network operations
rabin2 -i <target> | grep -iE "WSAStartup|socket|connect|bind|listen|send|recv|InternetOpen|HttpSendRequest|URLDownloadToFile|WinHttpOpen"

# Registry operations (persistence)
rabin2 -i <target> | grep -iE "RegOpenKey|RegSetValue|RegCreateKey|RegDeleteKey"

# Crypto operations
rabin2 -i <target> | grep -iE "CryptEncrypt|CryptDecrypt|CryptGenKey|CryptImportKey|BCryptEncrypt"

# Anti-debug
rabin2 -i <target> | grep -iE "IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|GetTickCount|QueryPerformanceCounter|OutputDebugString"
```

### Phase 7: Shellcode Analysis

If the target is raw shellcode or contains shellcode:

```bash
# Disassemble raw bytes as x86/x64
rasm2 -a x86 -b 32 -d -f <target> | head -50
# or for 64-bit:
rasm2 -a x86 -b 64 -d -f <target> | head -50

# Look for common shellcode patterns
r2 -q -c "e asm.arch=x86; e asm.bits=32; pd 50" <target> 2>/dev/null

# Search for shellcode signatures
rafind2 -x "558bec" <target>   # push ebp; mov ebp, esp (function prologue)
rafind2 -x "6a00" <target>      # push 0 (common in API calls)
rafind2 -x "ff15" <target>      # call [import] (indirect call)
rafind2 -x "e8" <target>        # call relative (direct call)
```

### Phase 8: Document Analysis (PDF/Office)

#### PDF files:
```bash
# PDF structure analysis
pdfid <target>

# Look for suspicious elements
pdfid <target> | grep -iE "JS|JavaScript|OpenAction|AA|Launch|EmbeddedFile|RichMedia|ObjStm"

# Parse PDF objects
pdf-parser <target> | head -100

# Extract JavaScript from PDF
pdf-parser --type /JS <target> 2>/dev/null
pdf-parser --type /JavaScript <target> 2>/dev/null

# Search for specific objects
pdf-parser --search "eval\|exec\|unescape\|fromCharCode" <target> 2>/dev/null
```

### Phase 9: Entropy & Packing Analysis

```bash
# Section entropy via r2
r2 -q -c "iS entropy" <target> 2>/dev/null

# Check for known packer signatures
rabin2 -I <target> | grep -i "packer\|compiler\|linker"
strings -a <target> | grep -iE "UPX|Themida|VMProtect|Enigma|ASPack|PECompact|MPRESS|Petite|NSPack"

# Binwalk entropy visualization
binwalk -E <target> 2>/dev/null
```

### Phase 10: Specific Function Deep-Dive

For functions identified as suspicious in earlier phases:

```bash
# Disassemble a specific function
r2 -q -c "aaa; pdf @ <function_name_or_address>" <target>

# Show function call graph
r2 -q -c "aaa; agc @ <function_name_or_address>" <target> 2>/dev/null

# Show cross-references TO a function (who calls it)
r2 -q -c "aaa; axt @ <function_name_or_address>" <target>

# Show cross-references FROM a function (what it calls)
r2 -q -c "aaa; axf @ <function_name_or_address>" <target>

# Hex dump of a specific region
r2 -q -c "px 256 @ <address>" <target>
```

## Validation Rules

1. **Imports**: Suspicious imports must be correlated with actual code that calls them (via xrefs)
2. **Strings**: Suspicious strings must be referenced by code (not just present in data sections)
3. **Packing**: Confirmed by high entropy + packer signatures + small import table
4. **Malicious behavior**: Requires multiple converging indicators, not a single suspicious import
5. **Anti-analysis**: Must find actual implementation, not just import presence

## Report Output

Write the report to `./reports/reverse-engineering-report.md`:

```markdown
# Reverse Engineering Report

**Date**: <date>
**File**: <filename>
**SHA256**: <hash>
**Architecture**: <arch/bits>
**Format**: <PE/ELF/Mach-O/raw>
**Compiler/Packer**: <if detected>
**Analyst**: Claude Code DFIR

## Executive Summary
<What this binary does in 2-3 sentences>

## Binary Properties
| Property | Value |
|----------|-------|
| Type | |
| Arch | |
| Bits | |
| Endianness | |
| Stripped | |
| Static/Dynamic | |
| PIE | |
| NX | |
| Canary | |
| RELRO | |
| Packer | |

## Capabilities Assessment
| Capability | Evidence | Risk |
|------------|----------|------|
| Process Injection | | |
| Network Communication | | |
| File System Manipulation | | |
| Registry Modification | | |
| Credential Access | | |
| Anti-Analysis | | |
| Persistence | | |
| Encryption/Encoding | | |

## Key Functions
| Address | Name | Purpose | Suspicious |
|---------|------|---------|------------|

## Findings

### Finding 1: <Title>
- **Category**: <capability>
- **Evidence**: <disassembly/imports/strings>
- **Validation**: <cross-references>
- **MITRE ATT&CK**: <technique ID>
- **Reproduce**:
  ```bash
  <exact r2/rabin2/command(s) the analyst can copy-paste to independently verify this finding>
  ```

## Control Flow Summary
<Description of program flow from entry point through key functions>

## Indicators of Compromise
| Type | Value | Context |
|------|-------|---------|

## Recommendations
<Numbered response actions and further analysis suggestions>
```

Create the `reports/` directory if it does not exist.
