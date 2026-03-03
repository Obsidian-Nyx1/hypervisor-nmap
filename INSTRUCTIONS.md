# Instructions

## What This Script Does

`assess.sh` runs `nmap` scans against either:

- one IP address
- a file containing multiple IP addresses

It is intended to give a quick service and vulnerability assessment workflow for hypervisor targets.

## How To Run It

Run it normally for no-sudo mode, or add `--sudo` for privileged scanning:

```bash
./assess.sh 192.168.1.100
./assess.sh --sudo 192.168.1.100
./assess.sh -f targets.txt
./assess.sh --sudo -f targets.txt
```

## What The Options Mean

- default mode: use unprivileged `nmap` execution
- `--sudo`: use privileged `nmap` execution
- `-f <file>`: read targets from a file

## Scan Phases

For multi-target runs, the script performs these phases per IP:

1. Port discovery
2. Service detection
3. Vulnerability checks

The first phase label changes based on privilege mode:

- `Stealth SYN scan` with `--sudo`
- `TCP connect scan` in default mode

## Output Notes

- If output goes to the terminal, each IP gets a `nmap_scan_<ip>.txt` file.
- If output is redirected, everything goes to the redirected destination instead.

## Validation Rules

- Only IPv4 addresses in dotted decimal format are accepted.
- Invalid entries in a target file stop execution with an error.
