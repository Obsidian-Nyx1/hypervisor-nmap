#!/bin/bash

# ------------------------------------------------------------
# Hypervisor Assessment Script using Nmap
# Usage: ./assess.sh <single-IP> | ./assess.sh -f <ip-list.txt>
# ------------------------------------------------------------

set -e  # Exit on error

# Colors for output (optional)
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage:"
    echo "  $0 <IP address>          Scan a single IP"
    echo "  $0 -f <file>              Scan all IPs listed in a file (one per line)"
    echo "Example:"
    echo "  $0 192.168.1.100"
    echo "  $0 -f targets.txt"
    exit 1
}

# Function to check if we can use sudo
check_sudo() {
    if command -v sudo &> /dev/null; then
        # Try to update sudo timestamp (will prompt for password if needed)
        if sudo -v &> /dev/null; then
            echo "sudo"
        else
            echo ""
        fi
    else
        echo ""
    fi
}

# Function to scan one IP
scan_ip() {
    local ip=$1
    local output_file="nmap_scan_${ip}.txt"
    local sudo_cmd=$2
    local -a nmap_args
    local -a cmd

    echo -e "${YELLOW}[*] Starting scan for IP: $ip${NC}"
    nmap_args=(-sV --script vuln --open --reason)

    if [ -t 1 ]; then
        echo -e "${YELLOW}[*] Output will be saved to: $output_file${NC}"
        nmap_args+=(-oN "$output_file")
    else
        echo -e "${YELLOW}[*] Stdout is redirected. Writing scan results to the redirected output only.${NC}"
    fi

    nmap_args+=("$ip")

    # If sudo is not available, warn user
    if [ -z "$sudo_cmd" ]; then
        echo -e "${RED}[!] Warning: sudo not available. Running nmap without root privileges.${NC}"
        echo -e "${RED}[!] Some scans (SYN scan, certain vulnerability checks) may be less accurate or fail.${NC}"
        cmd=(nmap "${nmap_args[@]}")
    else
        cmd=(sudo nmap "${nmap_args[@]}")
    fi

    # Execute the scan
    "${cmd[@]}"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Scan completed for $ip${NC}"
    else
        echo -e "${RED}[✗] Scan failed for $ip${NC}"
    fi
    echo "--------------------------------------------------------"
}

# -------------------- Main execution --------------------

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}Error: nmap is not installed. Please install nmap first.${NC}"
    exit 1
fi

# Determine sudo availability
SUDO_CMD=$(check_sudo)

# Parse arguments
if [ $# -eq 0 ]; then
    usage
fi

# Single IP case
if [ $# -eq 1 ] && [[ "$1" != "-f" ]]; then
    ip="$1"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        scan_ip "$ip" "$SUDO_CMD"
    else
        echo -e "${RED}Invalid IP format: $ip${NC}"
        exit 1
    fi

# File case
elif [ "$1" = "-f" ]; then
    if [ -z "$2" ]; then
        echo -e "${RED}Error: Missing file name after -f${NC}"
        usage
    fi
    if [ ! -f "$2" ]; then
        echo -e "${RED}Error: File $2 not found${NC}"
        exit 1
    fi

    echo -e "${GREEN}[*] Reading targets from file: $2${NC}"
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        # Skip empty lines and comments
        if [[ -z "$ip" || "$ip" =~ ^# ]]; then
            continue
        fi
        # Trim whitespace
        ip=$(echo "$ip" | xargs)
        scan_ip "$ip" "$SUDO_CMD"
    done < "$2"

else
    usage
fi

echo -e "${GREEN}[✔] All scans finished.${NC}"
