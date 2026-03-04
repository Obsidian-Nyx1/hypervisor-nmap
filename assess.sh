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
    echo "  $0 [--sudo] [-t0|-t1|-t2|-t3|-t4] <IP address>"
    echo "  $0 [--sudo] [-t0|-t1|-t2|-t3|-t4] -f <file>"
    echo "Example:"
    echo "  $0 192.168.1.100"
    echo "  $0 -t3 192.168.1.100"
    echo "  $0 --sudo 192.168.1.100"
    echo "  $0 -f targets.txt"
    echo "  $0 --sudo -t2 -f targets.txt"
    echo "Notes:"
    echo "  Default    Run nmap without sudo."
    echo "  --sudo     Run nmap through sudo. sudo will prompt if authentication is needed."
    echo "  -tN        Set Nmap timing template from 0 to 4 only. Default is -T4."
    echo "             Values above 4 are rejected."
    echo "  -h, --help Show this help message."
    exit 1
}

print_banner() {
    local mode_label=$1
    local target_label=$2

    echo "------------------------------------------------------------"
    echo "Hypervisor Assessment Script using Nmap"
    echo "Description : Scans one IP or a target file for open services and vulnerabilities."
    echo "Mode        : $mode_label"
    echo "Timing      : $TIMING_LABEL (capped at T4)"
    echo "Target      : $target_label"
    echo "Information : All runs execute discovery, service detection, vulnerability, and OS detection phases."
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

resolve_timing() {
    case "$1" in
        -t0|-t1|-t2|-t3|-t4)
            echo "-T${1#-t}"
            ;;
        -t[5-9]|-t[1-9][0-9]*)
            echo -e "${RED}Error: $1 exceeds the maximum allowed timing template. Use -t0 through -t4 only.${NC}"
            exit 1
            ;;
        -T[0-4])
            echo "${1}"
            ;;
        -T[5-9]|-T[1-9][0-9]*)
            echo -e "${RED}Error: $1 exceeds the maximum allowed timing template. Use -t0 through -t4 only.${NC}"
            exit 1
            ;;
        *)
            echo -e "${RED}Error: Invalid timing option '$1'. Use -t0 through -t4 only.${NC}"
            usage
            ;;
    esac
}

# Function to validate IP format
is_valid_ip() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

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

write_block() {
    local output_file=$1
    local text=$2

    if [ -n "$output_file" ]; then
        printf "%b" "$text" >> "$output_file"
    else
        printf "%b" "$text"
    fi
}

append_file() {
    local output_file=$1
    local source_file=$2

    if [ -n "$output_file" ]; then
        cat "$source_file" >> "$output_file"
    else
        cat "$source_file"
    fi
}

run_scan_capture() {
    local result_file=$1
    shift

    if "$@" > "$result_file" 2>&1; then
        return 0
    fi

    return 1
}

count_open_ports() {
    local result_file=$1

    grep -Ec '^[0-9]+/(tcp|udp)[[:space:]]+open([[:space:]]|$)' "$result_file" 2>/dev/null || true
}

phase_has_vuln_findings() {
    local result_file=$1

    awk '
        /^[0-9]+\/(tcp|udp)/ { current_port=$1; next }
        /^\|[_ ]?[A-Za-z0-9._-]+:/ {
            line=$0
            sub(/^\|[_ ]?/, "", line)
            split(line, parts, ":")
            if (parts[1] != "VULNERABLE" && parts[1] != "Not shown" && parts[1] != "Service Info") {
                found=1
                exit
            }
        }
        END { exit(found ? 0 : 1) }
    ' "$result_file"
}

extract_vuln_rows() {
    local result_file=$1

    awk '
        /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
            split($1, parts, "/")
            current_port=parts[1]
            current_proto=parts[2]
            current_service=$3
            next
        }
        /^\|[_ ]?[A-Za-z0-9._-]+:/ {
            line=$0
            sub(/^\|[_ ]?/, "", line)
            split(line, parts, ":")
            script_name=parts[1]
            if (script_name != "VULNERABLE" && script_name != "Not shown" && script_name != "Service Info") {
                print current_port "\t" current_proto "\t" current_service "\t" script_name
            }
        }
    ' "$result_file"
}

os_detected_value() {
    local result_file=$1
    local os_value=""

    os_value=$(grep -m1 '^OS details:' "$result_file" | cut -d: -f2- | xargs || true)
    if [ -z "$os_value" ]; then
        os_value=$(grep -m1 '^Aggressive OS guesses:' "$result_file" | cut -d: -f2- | xargs || true)
    fi
    if [ -z "$os_value" ]; then
        os_value=$(grep -m1 '^Running:' "$result_file" | cut -d: -f2- | xargs || true)
    fi

    if [ -z "$os_value" ]; then
        echo "Not identified"
    else
        echo "$os_value"
    fi
}

os_device_type_value() {
    local result_file=$1
    local value

    value=$(grep -m1 '^Device type:' "$result_file" | cut -d: -f2- | xargs || true)
    if [ -z "$value" ]; then
        echo "Not identified"
    else
        echo "$value"
    fi
}

os_distance_value() {
    local result_file=$1
    local value

    value=$(grep -m1 '^Network Distance:' "$result_file" | cut -d: -f2- | xargs || true)
    if [ -z "$value" ]; then
        echo "Not identified"
    else
        echo "$value"
    fi
}

summarize_phase() {
    local phase_key=$1
    local result_file=$2
    local scan_status=$3
    local open_ports=0

    if [ "$scan_status" -ne 0 ]; then
        echo "Scan command failed. See raw output below."
        return
    fi

    open_ports=$(count_open_ports "$result_file")

    case "$phase_key" in
        discovery)
            if [ "$open_ports" -gt 0 ]; then
                echo "Scan completed. Open ports found in discovery: $open_ports."
            else
                echo "Scan completed. No open ports were reported during discovery."
            fi
            ;;
        service)
            if [ "$open_ports" -gt 0 ]; then
                echo "Scan completed. Service detection returned $open_ports open port entry(s)."
            else
                echo "Scan completed. No open ports were available for service detection results."
            fi
            ;;
        vuln)
            if [ "$open_ports" -gt 0 ]; then
                if phase_has_vuln_findings "$result_file"; then
                    echo "Scan completed. Vulnerability scripts returned output for at least one open service."
                else
                    echo "Scan completed. Vulnerability scripts ran against open services, but no findings were reported by the NSE vuln scripts."
                fi
            else
                echo "Scan completed. No open ports were available for vulnerability script checks."
            fi
            ;;
        os)
            if grep -qi 'requires root privileges' "$result_file"; then
                echo "Scan completed. OS detection requires sudo/root privileges for reliable fingerprinting."
            elif grep -qi 'Too many fingerprints match' "$result_file" || grep -q '^OS details:' "$result_file" || grep -q '^Running:' "$result_file" || grep -q '^Aggressive OS guesses:' "$result_file"; then
                echo "Scan completed. OS detection produced a fingerprint result."
            else
                echo "Scan completed. OS detection did not identify a confident match."
            fi
            ;;
    esac
}

write_report_intro() {
    local ip=$1
    local output_file=$2
    local mode_label=$3
    local discovery_label=$4

    write_block "$output_file" "============================================================\n"
    write_block "$output_file" "Hypervisor Assessment Report\n"
    write_block "$output_file" "Target         : $ip\n"
    write_block "$output_file" "Privilege mode : $mode_label\n"
    write_block "$output_file" "Phase 1        : $discovery_label on the top 1000 ports\n"
    write_block "$output_file" "Phase 2        : Service/version detection on open ports\n"
    write_block "$output_file" "Phase 3        : NSE vulnerability scripts (--script vuln) on open ports\n"
    write_block "$output_file" "Phase 4        : OS detection (-O --osscan-guess)\n"
    write_block "$output_file" "Interpretation : If a phase summary says no open ports were found, Nmap still ran successfully but did not identify any open ports that matched the scan.\n"
    write_block "$output_file" "Interpretation : Vulnerability checks only produce findings when Nmap has an open service to test and a matching NSE vuln script returns output.\n"
    write_block "$output_file" "============================================================\n"
}

write_single_ip_summary_table() {
    local output_file=$1
    local ip=$2
    local discovery_file=$3
    local service_file=$4
    local vuln_file=$5
    local os_file=$6
    local border="+----------+--------+--------+----------------------+----------------------------------+\n"
    local found="false"
    local os_guess
    local device_type
    local network_distance
    local detection_status

    os_guess=$(os_detected_value "$os_file")
    device_type=$(os_device_type_value "$os_file")
    network_distance=$(os_distance_value "$os_file")

    if grep -qi 'requires root privileges' "$os_file"; then
        detection_status="Needs sudo/root privileges"
    elif [ "$os_guess" = "Not identified" ]; then
        detection_status="No confident OS fingerprint"
    else
        detection_status="OS fingerprint reported"
    fi

    write_block "$output_file" "\nSummary Table ($ip)\n"
    write_block "$output_file" "$border"
    write_block "$output_file" "| Type     | Port   | Proto  | Label                | Result                           |\n"
    write_block "$output_file" "$border"

    while IFS=$'\t' read -r port proto status reason; do
        [ -z "$port" ] && continue
        found="true"
        printf -v row '| %-8s | %-6s | %-6s | %-20.20s | %-32.32s |\n' "Port" "$port" "$proto" "$status" "$reason"
        write_block "$output_file" "$row"
    done < <(
        awk '
            /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
                split($1, parts, "/")
                port=parts[1]
                proto=parts[2]
                status=$2
                reason=""
                if (NF >= 4) {
                    for (i = 4; i <= NF; i++) {
                        reason = reason (reason ? " " : "") $i
                    }
                }
                if (reason == "") {
                    reason = "reported by nmap"
                }
                print port "\t" proto "\t" status "\t" reason
            }
        ' "$discovery_file"
    )

    while IFS=$'\t' read -r port proto service details; do
        [ -z "$port" ] && continue
        found="true"
        printf -v row '| %-8s | %-6s | %-6s | %-20.20s | %-32.32s |\n' "Service" "$port" "$proto" "$service" "$details"
        write_block "$output_file" "$row"
    done < <(
        awk '
            /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
                split($1, parts, "/")
                port=parts[1]
                proto=parts[2]
                service=$3
                details=""
                if (NF >= 4) {
                    for (i = 4; i <= NF; i++) {
                        details = details (details ? " " : "") $i
                    }
                }
                if (details == "") {
                    details = "No version string returned"
                }
                print port "\t" proto "\t" service "\t" details
            }
        ' "$service_file"
    )

    while IFS=$'\t' read -r port proto service script_name; do
        [ -z "$port" ] && continue
        found="true"
        printf -v row '| %-8s | %-6s | %-6s | %-20.20s | %-32.32s |\n' "Vuln" "$port" "$proto" "$service" "$script_name"
        write_block "$output_file" "$row"
    done < <(extract_vuln_rows "$vuln_file")

    if [ "$found" = "false" ]; then
        write_block "$output_file" "| none     | n/a    | n/a    | Findings             | No open ports or findings        |\n"
    fi

    printf -v row '| %-8s | %-6s | %-6s | %-20.20s | %-32.32s |\n' "OS" "n/a" "n/a" "OS guess" "$os_guess"
    write_block "$output_file" "$row"
    printf -v row '| %-8s | %-6s | %-6s | %-20.20s | %-32.32s |\n' "OS" "n/a" "n/a" "Device type" "$device_type"
    write_block "$output_file" "$row"
    printf -v row '| %-8s | %-6s | %-6s | %-20.20s | %-32.32s |\n' "OS" "n/a" "n/a" "Network distance" "$network_distance"
    write_block "$output_file" "$row"
    printf -v row '| %-8s | %-6s | %-6s | %-20.20s | %-32.32s |\n' "OS" "n/a" "n/a" "Detection status" "$detection_status"
    write_block "$output_file" "$row"
    write_block "$output_file" "$border"
}

write_ports_table() {
    local output_file=$1
    local ip=$2
    local result_file=$3
    local border="+-----------------+--------+--------+----------+--------------------------+\n"
    local found="false"

    write_block "$output_file" "\nPorts Summary ($ip)\n"
    write_block "$output_file" "$border"
    write_block "$output_file" "| IP              | Port   | Proto  | Status   | Reason                   |\n"
    write_block "$output_file" "$border"

    while IFS=$'\t' read -r port proto status reason; do
        [ -z "$port" ] && continue
        found="true"
        printf -v row '| %-15.15s | %-6s | %-6s | %-8s | %-24.24s |\n' "$ip" "$port" "$proto" "$status" "$reason"
        write_block "$output_file" "$row"
    done < <(
        awk '
            /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
                split($1, parts, "/")
                port=parts[1]
                proto=parts[2]
                status=$2
                reason=""
                if (NF >= 4) {
                    for (i = 4; i <= NF; i++) {
                        reason = reason (reason ? " " : "") $i
                    }
                }
                if (reason == "") {
                    reason = "reported by nmap"
                }
                print port "\t" proto "\t" status "\t" reason
            }
        ' "$result_file"
    )

    if [ "$found" = "false" ]; then
        printf -v row '| %-15.15s | %-6s | %-6s | %-8s | %-24.24s |\n' "$ip" "none" "n/a" "none" "No open ports reported"
        write_block "$output_file" "$row"
    fi

    write_block "$output_file" "$border"
}

write_services_table() {
    local output_file=$1
    local ip=$2
    local result_file=$3
    local border="+-----------------+--------+--------+------------------+----------------------------------+\n"
    local found="false"

    write_block "$output_file" "\nServices Summary ($ip)\n"
    write_block "$output_file" "$border"
    write_block "$output_file" "| IP              | Port   | Proto  | Service          | Details                          |\n"
    write_block "$output_file" "$border"

    while IFS=$'\t' read -r port proto service details; do
        [ -z "$port" ] && continue
        found="true"
        printf -v row '| %-15.15s | %-6s | %-6s | %-16.16s | %-32.32s |\n' "$ip" "$port" "$proto" "$service" "$details"
        write_block "$output_file" "$row"
    done < <(
        awk '
            /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
                split($1, parts, "/")
                port=parts[1]
                proto=parts[2]
                service=$3
                details=""
                if (NF >= 4) {
                    for (i = 4; i <= NF; i++) {
                        details = details (details ? " " : "") $i
                    }
                }
                if (details == "") {
                    details = "No version string returned"
                }
                print port "\t" proto "\t" service "\t" details
            }
        ' "$result_file"
    )

    if [ "$found" = "false" ]; then
        printf -v row '| %-15.15s | %-6s | %-6s | %-16.16s | %-32.32s |\n' "$ip" "none" "n/a" "none" "No services identified"
        write_block "$output_file" "$row"
    fi

    write_block "$output_file" "$border"
}

write_vuln_table() {
    local output_file=$1
    local ip=$2
    local result_file=$3
    local border="+-----------------+--------+--------+------------------+----------------------------------+\n"
    local found="false"

    write_block "$output_file" "\nVulnerability Summary ($ip)\n"
    write_block "$output_file" "$border"
    write_block "$output_file" "| IP              | Port   | Proto  | Service          | Vulnerability Script             |\n"
    write_block "$output_file" "$border"

    while IFS=$'\t' read -r port proto service script_name; do
        [ -z "$port" ] && continue
        found="true"
        printf -v row '| %-15.15s | %-6s | %-6s | %-16.16s | %-32.32s |\n' "$ip" "$port" "$proto" "$service" "$script_name"
        write_block "$output_file" "$row"
    done < <(extract_vuln_rows "$result_file")

    if [ "$found" = "false" ]; then
        printf -v row '| %-15.15s | %-6s | %-6s | %-16.16s | %-32.32s |\n' "$ip" "none" "n/a" "none" "No vulnerability findings"
        write_block "$output_file" "$row"
    fi

    write_block "$output_file" "$border"
}

write_os_table() {
    local output_file=$1
    local ip=$2
    local result_file=$3
    local border="+-----------------+----------------------+------------------------------------------+\n"
    local os_guess
    local device_type
    local network_distance
    local detection_status

    os_guess=$(os_detected_value "$result_file")
    device_type=$(os_device_type_value "$result_file")
    network_distance=$(os_distance_value "$result_file")

    if grep -qi 'requires root privileges' "$result_file"; then
        detection_status="Needs sudo/root privileges"
    elif [ "$os_guess" = "Not identified" ]; then
        detection_status="No confident OS fingerprint"
    else
        detection_status="OS fingerprint reported"
    fi

    write_block "$output_file" "\nOS Summary ($ip)\n"
    write_block "$output_file" "$border"
    write_block "$output_file" "| IP              | Field                | Value                                    |\n"
    write_block "$output_file" "$border"
    printf -v row '| %-15.15s | %-20s | %-40.40s |\n' "$ip" "OS guess" "$os_guess"
    write_block "$output_file" "$row"
    printf -v row '| %-15.15s | %-20s | %-40.40s |\n' "$ip" "Device type" "$device_type"
    write_block "$output_file" "$row"
    printf -v row '| %-15.15s | %-20s | %-40.40s |\n' "$ip" "Network distance" "$network_distance"
    write_block "$output_file" "$row"
    printf -v row '| %-15.15s | %-20s | %-40.40s |\n' "$ip" "Detection status" "$detection_status"
    write_block "$output_file" "$row"
    write_block "$output_file" "$border"
}

write_phase_details() {
    local output_file=$1
    local ip=$2
    local phase_title=$3
    local phase_description=$4
    local phase_summary=$5
    local result_file=$6
    shift 6

    write_block "$output_file" "\n=== $phase_title ($ip) ===\n"
    write_block "$output_file" "Purpose: $phase_description\n"
    write_block "$output_file" "Command: $(printf '%q ' "$@")\n"
    write_block "$output_file" "Status : $phase_summary\n"
    write_block "$output_file" "Raw Nmap output:\n"
    append_file "$output_file" "$result_file"
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
    local total_steps=$(( total_targets * 4 ))
    local show_progress="false"
    local discovery_label=""
    local -a scan_prefix
    local -a phase_cmd
    local -a nmap_base_cmd
    local discovery_file
    local service_file
    local vuln_file
    local os_file
    local discovery_status=0
    local service_status=0
    local vuln_status=0
    local os_status=0
    local discovery_summary=""
    local service_summary=""
    local vuln_summary=""
    local os_summary=""

    echo -e "${YELLOW}[*] Starting scan for IP: $ip${NC}"

    if [ -t 1 ]; then
        output_file="nmap_scan_${ip}.txt"
        : > "$output_file"
        echo -e "${YELLOW}[*] Output will be saved to: $output_file${NC}"
        show_progress="true"
    else
        echo -e "${YELLOW}[*] Stdout is redirected. Writing scan results to the redirected output only.${NC}"
    fi

    if [ -z "$sudo_cmd" ]; then
        echo -e "${YELLOW}[*] Running nmap without root privileges.${NC}"
        echo -e "${YELLOW}[*] Discovery will use a TCP connect scan instead of a SYN stealth scan.${NC}"
        scan_prefix=(nmap)
        discovery_label="TCP connect scan"
    else
        scan_prefix=(sudo nmap)
        discovery_label="Stealth SYN scan"
    fi

    nmap_base_cmd=("${scan_prefix[@]}" "$TIMING_OPTION")

    discovery_file=$(mktemp)
    service_file=$(mktemp)
    vuln_file=$(mktemp)
    os_file=$(mktemp)

    current_step=$(( (target_index - 1) * 4 + 1 ))
    if [ "$show_progress" = "true" ]; then
        draw_progress_bar "$current_step" "$total_steps" "$ip" "$discovery_label"
    fi
    phase_cmd=("${nmap_base_cmd[@]}" -Pn --top-ports 1000 --open --reason "$ip")
    if [ -n "$sudo_cmd" ]; then
        phase_cmd=("${nmap_base_cmd[@]}" -Pn -sS --top-ports 1000 --open --reason "$ip")
    else
        phase_cmd=("${nmap_base_cmd[@]}" -Pn -sT --top-ports 1000 --open --reason "$ip")
    fi
    if run_scan_capture "$discovery_file" "${phase_cmd[@]}"; then
        discovery_status=0
    else
        discovery_status=$?
    fi

    current_step=$(( (target_index - 1) * 4 + 2 ))
    if [ "$show_progress" = "true" ]; then
        draw_progress_bar "$current_step" "$total_steps" "$ip" "Service detection scan"
    fi
    phase_cmd=("${nmap_base_cmd[@]}" -Pn -sV --open --reason "$ip")
    if run_scan_capture "$service_file" "${phase_cmd[@]}"; then
        service_status=0
    else
        service_status=$?
    fi

    current_step=$(( (target_index - 1) * 4 + 3 ))
    if [ "$show_progress" = "true" ]; then
        draw_progress_bar "$current_step" "$total_steps" "$ip" "Vulnerability script scan"
    fi
    phase_cmd=("${nmap_base_cmd[@]}" -Pn -sV --script vuln --open --reason "$ip")
    if run_scan_capture "$vuln_file" "${phase_cmd[@]}"; then
        vuln_status=0
    else
        vuln_status=$?
    fi

    current_step=$(( (target_index - 1) * 4 + 4 ))
    if [ "$show_progress" = "true" ]; then
        draw_progress_bar "$current_step" "$total_steps" "$ip" "OS detection scan"
    fi
    phase_cmd=("${nmap_base_cmd[@]}" -Pn -O --osscan-guess "$ip")
    if run_scan_capture "$os_file" "${phase_cmd[@]}"; then
        os_status=0
    else
        os_status=$?
    fi

    if [ "$show_progress" = "true" ]; then
        printf '\n'
    fi

    discovery_summary=$(summarize_phase "discovery" "$discovery_file" "$discovery_status")
    service_summary=$(summarize_phase "service" "$service_file" "$service_status")
    vuln_summary=$(summarize_phase "vuln" "$vuln_file" "$vuln_status")
    os_summary=$(summarize_phase "os" "$os_file" "$os_status")

    write_report_intro "$ip" "$output_file" "$MODE_LABEL" "$discovery_label"
    if [ "$total_targets" -le 1 ]; then
        write_single_ip_summary_table "$output_file" "$ip" "$discovery_file" "$service_file" "$vuln_file" "$os_file"
    else
        write_ports_table "$output_file" "$ip" "$discovery_file"
        write_services_table "$output_file" "$ip" "$service_file"
        write_vuln_table "$output_file" "$ip" "$vuln_file"
        write_os_table "$output_file" "$ip" "$os_file"
    fi

    write_block "$output_file" "\nDetailed Results\n"

    if [ -n "$sudo_cmd" ]; then
        phase_cmd=(sudo nmap "$TIMING_OPTION" -Pn -sS --top-ports 1000 --open --reason "$ip")
    else
        phase_cmd=(nmap "$TIMING_OPTION" -Pn -sT --top-ports 1000 --open --reason "$ip")
    fi
    write_phase_details "$output_file" "$ip" "Phase 1: $discovery_label" "Identify open ports using the initial discovery pass." "$discovery_summary" "$discovery_file" "${phase_cmd[@]}"

    phase_cmd=("${nmap_base_cmd[@]}" -Pn -sV --open --reason "$ip")
    write_phase_details "$output_file" "$ip" "Phase 2: Service detection" "Fingerprint the versions of any open services Nmap can identify." "$service_summary" "$service_file" "${phase_cmd[@]}"

    phase_cmd=("${nmap_base_cmd[@]}" -Pn -sV --script vuln --open --reason "$ip")
    write_phase_details "$output_file" "$ip" "Phase 3: Vulnerability checks" "Run Nmap NSE vulnerability scripts against any open services." "$vuln_summary" "$vuln_file" "${phase_cmd[@]}"

    phase_cmd=("${nmap_base_cmd[@]}" -Pn -O --osscan-guess "$ip")
    write_phase_details "$output_file" "$ip" "Phase 4: OS detection" "Attempt to identify the target operating system from its network fingerprint." "$os_summary" "$os_file" "${phase_cmd[@]}"

    rm -f "$discovery_file" "$service_file" "$vuln_file" "$os_file"

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
TIMING_OPTION="-T4"
TIMING_LABEL="T4"

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --sudo)
            if [ -n "$SUDO_CMD" ]; then
                echo -e "${RED}Error: --sudo was provided more than once.${NC}"
                usage
            fi
            SUDO_CMD=$(resolve_mode "$1")
            MODE_LABEL="sudo"
            shift
            ;;
        -t*|-T*)
            TIMING_OPTION=$(resolve_timing "$1")
            TIMING_LABEL="${TIMING_OPTION#-}"
            shift
            ;;
        --*)
            resolve_mode "$1"
            ;;
        *)
            break
            ;;
    esac
done

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
