# Hypervisor-Nmp

`Hypervisor-Nmp` is a Bash-based Nmap wrapper for assessing one IPv4 target or a list of IPv4 targets with a consistent reporting format.

The script performs four phases per target:
- port discovery
- service/version detection
- NSE vulnerability checks
- OS detection

## Features

- single-IP and multi-IP scanning
- optional `--sudo` mode for privileged scans
- timing controls limited to `-T0` through `-T4`
- default timing locked to `-T4`
- terminal progress bar with per-phase status
- compact single-IP summary table
- IP-labelled multi-IP summary sections
- detailed raw Nmap output after the summary

## Requirements

- Bash
- `nmap`
- `sudo` only if you use `--sudo`

## Usage

```bash
./assess.sh <ip>
./assess.sh --sudo <ip>
./assess.sh -t3 <ip>
./assess.sh -f targets.txt
./assess.sh --sudo -t2 -f targets.txt
./assess.sh -h
```

## Options

- `--sudo`: run Nmap through `sudo`
- `-t0` to `-t4`: set the Nmap timing template
- default timing is `-T4`
- values above `-T4` are rejected
- `-f <file>`: scan targets from a text file
- `-h`, `--help`: show help

## Timing Policy

The script never exceeds `-T4`.

If the user does not specify a timing value, it uses `-T4` by default. If the user supplies `-t0`, `-t1`, `-t2`, `-t3`, or `-t4`, that value is applied to every Nmap phase. Any value above `-T4` is rejected before scanning starts.

## Input File Format

The target file must contain one IPv4 address per line. Empty lines and lines beginning with `#` are ignored.

Example:

```text
# Hypervisors
192.168.1.10
192.168.1.11
192.168.1.12
```

## Report Format

Each report starts with a header describing:
- target
- privilege mode
- timing policy
- scan phases

For a single IP, the report then shows one compact summary table that combines:
- ports
- services
- vulnerability findings
- OS detection

For multi-IP runs, the report uses separate summary sections, and each section header includes the target IP:
- `Ports Summary (<ip>)`
- `Services Summary (<ip>)`
- `Vulnerability Summary (<ip>)`
- `OS Summary (<ip>)`

After the summary, the report includes a `Detailed Results` section with:
- phase purpose
- exact Nmap command used
- phase status summary
- raw Nmap output

## Output Behavior

- terminal runs write per-target files as `nmap_scan_<ip>.txt`
- redirected runs write everything to the redirected destination
- no extra report files are created when stdout is redirected

### Report Artifact Policy

- report artifacts are local-only and must never be committed to this repository
- ignored artifact patterns: `nmap_scan_*.txt`, `reports/`, `bulk_report.txt`
- if a report file was previously tracked, untrack it with:

```bash
git rm --cached nmap_scan_*.txt
```

Example:

```bash
./assess.sh -f targets.txt > bulk_report.txt 2>&1
```

## Examples

Single target, default timing:

```bash
./assess.sh 203.0.113.42
```

Single target, slower timing:

```bash
./assess.sh -t2 203.0.113.42
```

Privileged scan:

```bash
./assess.sh --sudo 203.0.113.42
```

Multiple targets from file:

```bash
./assess.sh --sudo -t3 -f targets.txt
```

## Notes

- default mode uses a TCP connect discovery scan
- `--sudo` allows a stealth SYN discovery scan
- OS detection is more reliable with `--sudo`
- vulnerability script phases can take noticeably longer than discovery scans
