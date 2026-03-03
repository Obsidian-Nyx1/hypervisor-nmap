#!/bin/bash

# ------------------------------------------------------------
# Hypervisor Assessment Script using Nmap
# Usage: ./assess.sh [--sudo] <single-IP> | ./assess.sh [--sudo] -f <ip-list.txt>
# ------------------------------------------------------------

set -e  # Exit on error

# Colors for output (optional)
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BAR_WIDTH=30

# Function to display usage
usage() {
    echo "Usage:"
    echo "  $0 [--sudo] <IP address>"
    echo "  $0 [--sudo] -f <file>"
    echo "Example:"
    echo "  $0 192.168.1.100"
    echo "  $0 --sudo 192.168.1.100"
    echo "  $0 -f targets.txt"
    echo "  $0 --sudo -f targets.txt"
    echo "Notes:"
    echo "  Default    Run nmap without sudo."
    echo "  --sudo     Run nmap through sudo. sudo will prompt if authentication is needed."
    exit 1
}

print_banner() {
    local mode_label=$1
    local target_label=$2

    echo "------------------------------------------------------------"
    echo "Hypervisor Assessment Script using Nmap"
    echo "Description : Scans one IP or a target file for open services and vulnerabilities."
    echo "Mode        : $mode_label"
    echo "Target      : $target_label"
    echo "Information : Single-IP runs use one combined scan. Multi-IP file runs show phase progress."
    echo "Instructions: Default mode is unprivileged. Add --sudo only when you want a privileged scan."
    if [ -t 1 ]; then
        echo "Output      : Results save to nmap_scan_<ip>.txt unless stdout is redirected."
    else
        echo "Output      : Stdout is redirected, so results will be written to the redirected output."
    fi
    echo "------------------------------------------------------------"
}

resolve_mode() {
    case "$1" in
        --sudo)
            if ! command -v sudo &> /dev/null; then
                echo -e "${RED}Error: sudo is not installed, so --sudo cannot be used.${NC}"
                exit 1
            fi
            echo "sudo"
            ;;
        *)
            echo -e "${RED}Error: Invalid option '$1'. Only --sudo is supported.${NC}"
            usage
            ;;
    esac
}

# Function to validate IP format
is_valid_ip() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# Progress bar for multi-IP scans only
draw_progress_bar() {
    local current=$1
    local total=$2
    local ip=$3
    local phase=$4
    local percent=0
    local filled=0
    local empty=0
    local bar=""

    if [ "$total" -gt 0 ]; then
        percent=$(( current * 100 / total ))
        filled=$(( current * BAR_WIDTH / total ))
    fi

    empty=$(( BAR_WIDTH - filled ))
    bar=$(printf '%*s' "$filled" '' | tr ' ' '#')
    bar+=$(printf '%*s' "$empty" '')

    printf "\r${GREEN}[%-${BAR_WIDTH}s] %3d%%${NC} [%d/%d] %s | %s" \
        "$bar" "$percent" "$current" "$total" "$ip" "$phase"
}

run_scan_command() {
    local output_file=$1
    shift

    if [ -n "$output_file" ]; then
        "$@" >> "$output_file" 2>&1
    else
        "$@"
    fi
}

run_scan_phase() {
    local ip=$1
    local output_file=$2
    local phase_title=$3
    shift 3

    if [ -n "$output_file" ]; then
        printf '\n=== %s (%s) ===\n' "$phase_title" "$ip" >> "$output_file"
    fi

    run_scan_command "$output_file" "$@"
}

# Function to scan one IP
scan_ip() {
    local ip=$1
    local sudo_cmd=$2
    local multi_mode=$3
    local target_index=${4:-1}
    local total_targets=${5:-1}
    local output_file=""
    local current_step=0
    local total_steps=$(( total_targets * 3 ))
    local discovery_label=""
    local -a scan_prefix
    local -a phase_cmd

    echo -e "${YELLOW}[*] Starting scan for IP: $ip${NC}"

    if [ -t 1 ]; then
        output_file="nmap_scan_${ip}.txt"
        echo -e "${YELLOW}[*] Output will be saved to: $output_file${NC}"
    else
        echo -e "${YELLOW}[*] Stdout is redirected. Writing scan results to the redirected output only.${NC}"
    fi

    if [ -z "$sudo_cmd" ]; then
        echo -e "${RED}[!] Warning: sudo not available. Running nmap without root privileges.${NC}"
        echo -e "${RED}[!] SYN stealth scan will fall back to a TCP connect scan.${NC}"
        scan_prefix=(nmap)
        discovery_label="TCP connect scan"
    else
        scan_prefix=(sudo nmap)
        discovery_label="Stealth SYN scan"
    fi

    if [ "$multi_mode" = "true" ]; then
        current_step=$(( (target_index - 1) * 3 + 1 ))
        draw_progress_bar "$current_step" "$total_steps" "$ip" "$discovery_label"
        phase_cmd=("${scan_prefix[@]}" -Pn --top-ports 1000 --open --reason "$ip")
        if [ -n "$sudo_cmd" ]; then
            phase_cmd=("${scan_prefix[@]}" -Pn -sS --top-ports 1000 --open --reason "$ip")
        else
            phase_cmd=("${scan_prefix[@]}" -Pn -sT --top-ports 1000 --open --reason "$ip")
        fi
        run_scan_phase "$ip" "$output_file" "Phase 1: $discovery_label" "${phase_cmd[@]}"

        current_step=$(( (target_index - 1) * 3 + 2 ))
        draw_progress_bar "$current_step" "$total_steps" "$ip" "Service detection scan"
        phase_cmd=("${scan_prefix[@]}" -Pn -sV --open --reason "$ip")
        run_scan_phase "$ip" "$output_file" "Phase 2: Service detection" "${phase_cmd[@]}"

        current_step=$(( (target_index - 1) * 3 + 3 ))
        draw_progress_bar "$current_step" "$total_steps" "$ip" "Vulnerability script scan"
        phase_cmd=("${scan_prefix[@]}" -Pn -sV --script vuln --open --reason "$ip")
        run_scan_phase "$ip" "$output_file" "Phase 3: Vulnerability checks" "${phase_cmd[@]}"
        printf '\n'
    else
        phase_cmd=("${scan_prefix[@]}" -Pn -sV --script vuln --open --reason "$ip")
        run_scan_phase "$ip" "$output_file" "Combined scan" "${phase_cmd[@]}"
    fi

    echo -e "${GREEN}[✓] Scan completed for $ip${NC}"
    echo "--------------------------------------------------------"
}

collect_targets() {
    local file=$1
    local line
    local ip

    TARGETS=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -z "$line" || "$line" =~ ^# ]]; then
            continue
        fi

        ip=$(echo "$line" | xargs)
        if ! is_valid_ip "$ip"; then
            echo -e "${RED}Invalid IP format in $file: $ip${NC}"
            exit 1
        fi

        TARGETS+=("$ip")
    done < "$file"

    if [ "${#TARGETS[@]}" -eq 0 ]; then
        echo -e "${RED}Error: No valid IPs found in $file${NC}"
        exit 1
    fi
}

# -------------------- Main execution --------------------

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}Error: nmap is not installed. Please install nmap first.${NC}"
    exit 1
fi

TARGETS=()

# Parse arguments
if [ $# -eq 0 ]; then
    usage
fi

SUDO_CMD=""
MODE_LABEL="no-sudo"
if [ "$1" = "--sudo" ]; then
    SUDO_CMD=$(resolve_mode "$1")
    MODE_LABEL="sudo"
    shift
elif [[ "$1" == --* ]]; then
    resolve_mode "$1"
fi

if [ $# -eq 0 ]; then
    usage
fi

# Single IP case
if [ $# -eq 1 ] && [[ "$1" != "-f" ]]; then
    ip="$1"
    if is_valid_ip "$ip"; then
        print_banner "$MODE_LABEL" "$ip"
        scan_ip "$ip" "$SUDO_CMD" "false"
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

    print_banner "$MODE_LABEL" "file:$2"
    echo -e "${GREEN}[*] Reading targets from file: $2${NC}"
    collect_targets "$2"

    total_targets=${#TARGETS[@]}
    multi_mode="false"
    if [ "$total_targets" -gt 1 ] && [ -t 1 ]; then
        multi_mode="true"
    fi

    for i in "${!TARGETS[@]}"; do
        scan_ip "${TARGETS[$i]}" "$SUDO_CMD" "$multi_mode" "$(( i + 1 ))" "$total_targets"
    done

else
    usage
fi

echo -e "${GREEN}[✔] All scans finished.${NC}"
