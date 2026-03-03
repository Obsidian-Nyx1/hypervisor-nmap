# Hypervisor Nmap Assessment

`assess.sh` is a Bash wrapper around `nmap` for scanning a single IP address or a file of IPs.

## Features

- Optional `--sudo` mode, with no-sudo as the default
- Single target scanning
- Multi-target file scanning
- Multi-target progress bar with scan phase labels
- Single redirected output stream when stdout is redirected

## Requirements

- Bash
- `nmap`
- `sudo` only if you choose `--sudo`

## Usage

```bash
./assess.sh 192.168.1.100
./assess.sh --sudo 192.168.1.100
./assess.sh -f targets.txt
./assess.sh --sudo -f targets.txt
```

## Modes

- default: runs `nmap` without `sudo`
- `--sudo`: runs `nmap` through `sudo`. This can prompt for your sudo password if your session is not already authenticated.

## Output Behavior

- Normal terminal run:
  - Single-IP scans save to `nmap_scan_<ip>.txt`
  - Multi-IP scans save each target to its own `nmap_scan_<ip>.txt`
- Redirected run such as `./assess.sh 192.168.1.10 > output.txt 2>&1`:
  - results are written to the redirected output
  - extra `nmap_scan_<ip>.txt` files are not created

## Multi-IP Progress

When using `-f` with more than one target and output is going to a terminal, the script shows:

- overall progress bar
- current IP being scanned
- current phase:
  - `Stealth SYN scan` when using `--sudo`
  - `TCP connect scan` in default mode
  - `Service detection scan`
  - `Vulnerability script scan`

## Input File Format

The file passed to `-f` should contain one IP per line. Empty lines and lines starting with `#` are ignored.

Example:

```text
# Hypervisors
192.168.1.10
192.168.1.11
192.168.1.12
```
