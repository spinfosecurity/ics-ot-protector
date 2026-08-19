#!/usr/bin/env bash
# ==============================================================================
# WUP WUP - Water Utility Protector (Bash)
#
# SYNOPSIS:
#   Interactive threat detector for water/wastewater utilities.
#   "WUP WUP" - Emergency response for critical infrastructure protection.
#
#   Updated August 2026 with latest CISA ICS advisories and threat intelligence.
#
# WHAT THIS DOES:
#   ✓ Scans OT subnets for internet-exposed PLCs, HMIs, and remote access
#   ✓ Detects RDP (3389), VNC (5900), SSH (22) - primary attack vectors
#   ✓ Identifies EtherNet/IP (44818, 2222), Modbus (502), S7 (102) exposure
#   ✓ Prioritizes findings by severity (CRITICAL vs HIGH)
#   ✓ Provides CISA-aligned remediation guidance
#   ✓ Generates JSON scan report (optional)
#   ✓ Parallel per-host scanning (up to 50 concurrent workers)
#
# WHAT THIS DOES NOT DO:
#   ✗ Does NOT test credentials or attempt authentication
#   ✗ Does NOT modify system configurations
#   ✗ Does NOT scan IT networks (OT/SCADA focus only)
#   ✗ Does NOT replace professional penetration testing
#   ✗ Does NOT detect active malware or intrusions
#   ✗ Does NOT work over IPv6 (IPv4 only)
#   ✗ Does NOT scan non-/24 subnets
#
# AUTHORIZED USE ONLY:
#   Defensive security assessment by authorized personnel only.
#   Only scan networks you own or have explicit written permission to test.
#
# Version:  3.3.0
# Reference: CISA Alert AA26-097A (2026-07-30)
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../_shared/load_sector_config.sh
source "${REPO_ROOT}/scanners/_shared/load_sector_config.sh"
# shellcheck source=../_shared/scanner_helpers.sh
source "${REPO_ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=../_shared/export_scan_report.sh
source "${REPO_ROOT}/scanners/_shared/export_scan_report.sh"
initialize_water_config

# ---------------------------------------------------------------------------- #
# Color helpers
# ---------------------------------------------------------------------------- #
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
DARK_YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

c()  { printf "${1}%s${RESET}" "$2"; }
cl() { printf "${1}%s${RESET}\n" "$2"; }

# ---------------------------------------------------------------------------- #
# Port / protocol tables loaded from config/sectors/water.yaml
# ---------------------------------------------------------------------------- #

get_threat_context() {
    local key="$1"
    if [[ -n "${THREAT_CONTEXT[$key]:-}" ]]; then
        echo "${THREAT_CONTEXT[$key]}"
    else
        echo "Exposed service — review access controls"
    fi
}

# ---------------------------------------------------------------------------- #
# UI helpers
# ---------------------------------------------------------------------------- #
show_intro() {
    clear
    cl "$CYAN" ""
    cl "$CYAN" "███████╗██╗███╗   ██╗ █████╗ ████████╗██╗ ██████╗ █████╗ ██╗     ██╗    ██╗"
    cl "$CYAN" "██╔════╝██║████╗  ██║██╔══██╗╚══██╔══╝██║██╔════╝██╔══██╗██║     ██║    ██║"
    cl "$CYAN" "█████╗  ██║██╔██╗ ██║███████║   ██║   ██║██║     ███████║██║     ██║ █╗ ██║"
    cl "$CYAN" "██╔══╝  ██║██║╚██╗██║██╔══██║   ██║   ██║██║     ██╔══██║██║     ██║███╗██║"
    cl "$CYAN" "██║     ██║██║ ╚████║██║  ██║   ██║   ██║╚██████╗██║  ██║███████╗╚███╔███╔╝"
    cl "$CYAN" "╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝"
    cl "$CYAN" ""
    cl "$WHITE" "WATER UTILITY PROTECTOR"
    cl "$WHITE" "WUP WUP - Emergency Response for Water Security"
    echo ""
    printf "${WHITE}Version: %s | Updated: August 2026${RESET}\n" "$SCRIPT_VERSION"
    printf "${WHITE}Reference: %s${RESET}\n" "$SCRIPT_REFERENCE"
    echo ""

    cl "$WHITE" "================================================================================"
    echo ""
    cl "$WHITE" "Enhanced with CISA Alert AA26-097A Intelligence (July 2026 Water Sector Attacks)"
    echo ""
    cl "$WHITE" "What This Does:"
    cl "$GRAY"  "  ✓ Scans OT subnets for exposed PLCs, HMIs, and remote access points"
    cl "$GRAY"  "  ✓ Detects RDP (3389), VNC (5900), SSH (22) - primary attack vectors"
    cl "$GRAY"  "  ✓ Identifies EtherNet/IP (44818, 2222), Modbus (502), S7 (102) exposure"
    cl "$GRAY"  "  ✓ Prioritizes findings by severity (CRITICAL vs HIGH)"
    cl "$GRAY"  "  ✓ Provides CISA-aligned remediation guidance"
    cl "$GRAY"  "  ✓ Generates JSON scan report (optional)"
    echo ""
    cl "$WHITE" "What This Does NOT Do:"
    cl "$GRAY"  "  ✗ Does NOT test credentials or attempt authentication"
    cl "$GRAY"  "  ✗ Does NOT modify system configurations"
    cl "$GRAY"  "  ✗ Does NOT scan IT networks (OT/SCADA focus only)"
    cl "$GRAY"  "  ✗ Does NOT replace professional penetration testing"
    cl "$GRAY"  "  ✗ Does NOT detect active malware or intrusions"
    cl "$GRAY"  "  ✗ Does NOT work over IPv6 (IPv4 only)"
    cl "$GRAY"  "  ✗ Does NOT scan non-/24 subnets"
    echo ""
    cl "$WHITE" "Technical Limitations:"
    cl "$GRAY"  "  • TCP port scan only (no UDP, no banner grabbing)"
    cl "$GRAY"  "  • Single-threaded (scan time scales with subnet count and timeout)"
    cl "$GRAY"  "  • May produce false negatives behind aggressive firewalls"
    cl "$GRAY"  "  • Requires local network access"
    echo ""
    cl "$YELLOW" "AUTHORIZED USE ONLY:"
    cl "$GRAY"   "  This tool is for defensive security assessment by authorized personnel only."
    cl "$GRAY"   "  Only scan networks you own or have explicit written permission to test."
    cl "$GRAY"   "  Unauthorized scanning may violate federal and state laws."
    echo ""
    cl "$WHITE" "================================================================================"
    echo ""
    printf "${YELLOW}Press Enter to begin configuration or Ctrl+C to exit...${RESET}"
    read -r _
}

show_header() {
    local title="$1" subtitle="${2:-}"
    echo ""
    cl "$CYAN" "============================================"
    printf "${CYAN}  %s${RESET}\n" "$title"
    if [[ -n "$subtitle" ]]; then
        printf "${GRAY}  %s${RESET}\n" "$subtitle"
    fi
    cl "$CYAN" "============================================"
    echo ""
}

show_scan_header() {
    local subnet="$1"
    echo ""
    cl "$CYAN" "┌──────────────────────────────────────────────────┐"
    printf "${CYAN}│${RESET}${WHITE} SCAN: %-44s${CYAN}│${RESET}\n" "$subnet"
    printf "${CYAN}│${RESET}${GRAY} Started: %-41s${CYAN}│${RESET}\n" "$(date '+%H:%M:%S')"
    cl "$CYAN" "└──────────────────────────────────────────────────┘"
}

show_scan_complete() {
    local elapsed_sec="$1" findings_count="$2"
    local content=" COMPLETE: ${elapsed_sec}s, ${findings_count} findings"
    local pad=$(( 47 - ${#content} ))
    (( pad < 0 )) && pad=0
    echo ""
    printf "  ${GREEN}┌%s┐${RESET}\n" "$(printf '─%.0s' $(seq 1 48))"
    printf "  ${GREEN}│${RESET}${WHITE}%s%*s${GREEN}│${RESET}\n" "$content" "$pad" ""
    printf "  ${GREEN}└%s┘${RESET}\n" "$(printf '─%.0s' $(seq 1 48))"
}

show_progress() {
    local current="$1" total="$2" start_epoch="$3"
    local elapsed=$(( $(date +%s) - start_epoch ))
    local rate=0
    (( elapsed > 0 )) && rate=$(echo "scale=1; $current / $elapsed" | bc 2>/dev/null || echo "?")
    local pct=$(( current * 100 / total ))
    local filled=$(( pct / 5 ))
    local empty=$(( 20 - filled ))
    local bar="["
    bar+=$(printf '█%.0s' $(seq 1 $filled) 2>/dev/null || true)
    bar+=$(printf '░%.0s' $(seq 1 $empty) 2>/dev/null || true)
    bar+="]"
    printf "\r${GRAY}  %s %3d%% (%d/%d IPs) - %s IPs/sec     ${RESET}" "$bar" "$pct" "$current" "$total" "$rate"
}

# ---------------------------------------------------------------------------- #
# Configuration steps
# ---------------------------------------------------------------------------- #
ask_subnets() {
    clear
    show_header "Step 1: Configure Scan Targets"

    cl "$WHITE" "Which OT subnets would you like to scan?"
    cl "$GRAY"  "  • Enter up to 5 subnets in format: 192.168.10.0/24"
    cl "$GRAY"  "  • Press Enter after each subnet"
    cl "$GRAY"  "  • Press Enter on empty line to finish"
    echo ""

    SUBNETS=()
    local subnet_count=0

    while (( subnet_count < 5 )); do
        (( subnet_count++ )) || true
        printf "  Subnet #%d: " "$subnet_count"
        read -r subnet

        if [[ -z "$subnet" ]]; then
            break
        fi

        if [[ "$subnet" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/([0-9]{1,2})$ ]]; then
            local prefix="${BASH_REMATCH[1]}"
            if [[ "$prefix" -eq 24 ]]; then
                SUBNETS+=("$subnet")
                printf "  ${GREEN}✓ Added: %s${RESET}\n" "$subnet"
            else
                cl "$RED" "  ✗ Only /24 subnets are supported"
                (( subnet_count-- )) || true
            fi
        else
            cl "$RED" "  ✗ Invalid format. Use: 192.168.10.0/24"
            (( subnet_count-- )) || true
        fi
    done

    if [[ "${#SUBNETS[@]}" -eq 0 ]]; then
        echo ""
        cl "$RED" "  [!] No subnets entered. Exiting..."
        sleep 2
        exit 1
    fi
}

ask_timeout() {
    clear
    show_header "Step 2: Set Scan Timeout"

    cl "$WHITE" "Connection timeout per IP (in seconds):"
    echo ""
    cl "$CYAN" "  Recommended Settings:"
    cl "$GRAY"  "  ┌────────────┬──────────────────────────────────────────┐"
    cl "$GRAY"  "  │ 1 second   │ Fast but may miss slow devices           │"
    cl "$GREEN" "  │ 2 seconds  │ Balanced (recommended for most networks) │"
    cl "$GRAY"  "  │ 3-5 seconds│ Slower but more thorough                 │"
    cl "$GRAY"  "  └────────────┴──────────────────────────────────────────┘"
    echo ""

    TIMEOUT=""
    while [[ -z "$TIMEOUT" ]]; do
        printf "  Enter timeout (1-30 seconds, default: 2): "
        read -r timeout_input

        if [[ -z "$timeout_input" ]]; then
            TIMEOUT=2
        elif [[ "$timeout_input" =~ ^[0-9]+$ ]]; then
            if (( timeout_input >= 1 && timeout_input <= 30 )); then
                TIMEOUT="$timeout_input"
            else
                cl "$RED" "  ✗ Please enter a value between 1 and 30"
            fi
        else
            cl "$RED" "  ✗ Invalid input. Enter a number between 1 and 30"
        fi
    done
}

ask_export_report() {
    clear
    show_header "Step 3: Export Options"

    cl "$WHITE" "Would you like to save a JSON scan report?"
    echo ""
    cl "$GRAY"  "  • Report includes all findings with timestamps"
    cl "$GRAY"  "  • Standard JSON format shared across all sector scanners"
    cl "$GRAY"  "  • Saved to: ~/WaterUtilitySecurity/Reports/"
    echo ""

    printf "  Save report? (Y/N): "
    read -r export_input
    EXPORT_REPORT=false
    [[ "$export_input" =~ ^[Yy] ]] && EXPORT_REPORT=true
}

confirm_scan() {
    clear
    show_header "Step 4: Confirm Configuration"

    cl "$WHITE" "Configuration Summary:"
    echo ""
    cl "$YELLOW" "  Subnets to scan:"
    for subnet in "${SUBNETS[@]}"; do
        printf "${WHITE}    • %s${RESET}\n" "$subnet"
    done
    echo ""

    local total_ips=$(( ${#SUBNETS[@]} * 254 ))
    local total_ports=$(( ${#REMOTE_ACCESS_PORTS[@]} + ${#OT_PROTOCOL_PORTS[@]} ))
    local worst_case_min
    worst_case_min=$(echo "scale=1; ${#SUBNETS[@]} * 254 * $TIMEOUT * $total_ports / 60" | bc 2>/dev/null || echo "?")

    printf "${YELLOW}  Timeout:                  %s seconds per IP${RESET}\n" "$TIMEOUT"
    printf "${YELLOW}  Total IPs:                %s${RESET}\n" "$total_ips"
    printf "${YELLOW}  Estimated time (worst case): ~%s minutes${RESET}\n" "$worst_case_min"
    printf "${YELLOW}  Report export:            %s${RESET}\n" "$(if $EXPORT_REPORT; then echo 'Yes'; else echo 'No'; fi)"
    echo ""

    printf "  Start scan? (Y/N): "
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        echo ""
        cl "$YELLOW" "  Scan cancelled."
        sleep 2
        exit 0
    fi
}

# ---------------------------------------------------------------------------- #
# Report generation
# ---------------------------------------------------------------------------- #
generate_report() {
    local report_dir="${HOME}/WaterUtilitySecurity/Reports"
    mkdir -p "$report_dir" 2>/dev/null || true

    if ! command -v jq >/dev/null 2>&1; then
        echo "generate_report requires jq" >&2
        return 1
    fi

    local findings_json='[]'
    for entry in "${FINDINGS_ALL[@]}"; do
        IFS='|' read -r sev ip port service threat_type threat_ctx action <<< "$entry"
        findings_json=$(jq -n \
            --argjson arr "$findings_json" \
            --arg ts "$(date '+%Y-%m-%dT%H:%M:%S')" \
            --arg host "$ip" \
            --argjson port "$port" \
            --arg service "$service" \
            --arg severity "$sev" \
            --arg category "$threat_type" \
            --arg description "$threat_ctx" \
            --arg remediation "$action" \
            '$arr + [{Timestamp:$ts, Host:$host, Port:$port, Service:$service, Severity:$severity, Category:$category, Description:$description, Remediation:$remediation}]')
    done

    export_scan_report_write "$report_dir" "WUP-results" "water" "WUP WUP" "$findings_json"
}

# Scan all ports on one IP; write pipe-delimited findings to out_file.
scan_host() {
    local ip="$1" timeout_sec="$2" out_file="$3"
    for entry in "${REMOTE_ACCESS_PORTS[@]}"; do
        IFS='|' read -r port service severity <<< "$entry"
        if test_tcp_port "$ip" "$port" "$timeout_sec"; then
            local token
            token=$(echo "$service" | grep -oE '^[A-Za-z0-9/]+')
            local ctx
            ctx=$(get_threat_context "$token")
            if [[ "$severity" == "CRITICAL" ]]; then
                echo "CRITICAL|${ip}|${port}|${service}|Remote Access - Immediate Threat|${ctx}|BLOCK IMMEDIATELY or restrict to VPN only" >> "$out_file"
            else
                echo "HIGH|${ip}|${port}|${service}|Web HMI Exposure|${ctx}|Restrict to engineering VLAN; implement MFA" >> "$out_file"
            fi
        fi
    done
    for entry in "${OT_PROTOCOL_PORTS[@]}"; do
        IFS='|' read -r port protocol <<< "$entry"
        if test_tcp_port "$ip" "$port" "$timeout_sec"; then
            local token
            token=$(echo "$protocol" | grep -oE '^[A-Za-z0-9/]+')
            local ctx
            ctx=$(get_threat_context "$token")
            echo "HIGH|${ip}|${port}|${protocol}|OT Protocol Exposure|${ctx}|Remove from internet; implement firewall rules" >> "$out_file"
        fi
    done
}

# ---------------------------------------------------------------------------- #
# Main
# ---------------------------------------------------------------------------- #
main() {
    # Global state
    SUBNETS=()
    TIMEOUT=2
    EXPORT_REPORT=false
    FINDINGS_ALL=()
    CRITICAL_COUNT=0
    HIGH_COUNT=0
    TOTAL_SCANNED=0
    SCAN_DURATION=0

    show_intro
    ask_subnets
    ask_timeout
    ask_export_report
    confirm_scan

    clear
    show_header "WUP WUP - Starting Threat Detection" "Scanning for ACTIVE THREAT VECTORS"

    printf "${WHITE}Subnets: %s${RESET}\n" "${SUBNETS[*]}"
    printf "${WHITE}Timeout: %ss per IP${RESET}\n" "$TIMEOUT"
    cl "$WHITE" "Scan Type: TCP Port Scan (OT + Remote Access)"
    echo ""

    local start_epoch
    start_epoch=$(date +%s)

    local max_workers=50
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    export -f scan_host get_threat_context
    export REMOTE_ACCESS_PORTS OT_PROTOCOL_PORTS

    for subnet in "${SUBNETS[@]}"; do
        local network_prefix
        network_prefix=$(get_network_prefix "$subnet")
        local subnet_start_epoch
        subnet_start_epoch=$(date +%s)
        local subnet_tmp="${tmp_dir}/${subnet//\//_}"
        mkdir -p "$subnet_tmp"

        show_scan_header "$subnet"

        local active_workers=0
        local completed=0

        for i in $(seq 1 254); do
            local ip="${network_prefix}.${i}"
            local out_file="${subnet_tmp}/${i}.findings"

            # Throttle: wait if at max concurrency
            while (( active_workers >= max_workers )); do
                wait -n 2>/dev/null || wait
                (( active_workers-- )) || true
                (( completed++ )) || true
                if (( completed % 25 == 0 )); then
                    echo ""
                    show_progress "$completed" 254 "$subnet_start_epoch"
                fi
            done

            scan_host "$ip" "$TIMEOUT" "$out_file" &
            (( active_workers++ )) || true
        done

        # Drain remaining workers
        while (( active_workers > 0 )); do
            wait -n 2>/dev/null || wait
            (( active_workers-- )) || true
            (( completed++ )) || true
        done
        echo ""

        # Collect and display results in IP order
        local subnet_findings=0
        for i in $(seq 1 254); do
            local out_file="${subnet_tmp}/${i}.findings"
            [[ -f "$out_file" ]] || continue
            while IFS= read -r line; do
                IFS='|' read -r sev ip port service threat_type threat_ctx action <<< "$line"
                if [[ "$sev" == "CRITICAL" ]]; then
                    printf "${RED}  [!!! CRITICAL !!!] %s:%s - %s${RESET}\n" "$ip" "$port" "$service"
                    printf "${RED}      %s${RESET}\n" "$threat_ctx"
                    printf "${YELLOW}      Action: %s${RESET}\n" "$action"
                    (( CRITICAL_COUNT++ )) || true
                else
                    local color="$YELLOW"
                    [[ "$threat_type" == "OT Protocol Exposure" ]] && color="$MAGENTA"
                    printf "${color}  [!! HIGH !!] %s:%s - %s${RESET}\n" "$ip" "$port" "$service"
                    printf "${color}      %s${RESET}\n" "$threat_ctx"
                    printf "${DARK_YELLOW}      Action: %s${RESET}\n" "$action"
                    (( HIGH_COUNT++ )) || true
                fi
                FINDINGS_ALL+=("$line")
                (( subnet_findings++ )) || true
            done < "$out_file"
        done

        (( TOTAL_SCANNED += 254 )) || true
        local subnet_elapsed=$(( $(date +%s) - subnet_start_epoch ))
        show_scan_complete "$subnet_elapsed" "$subnet_findings"
    done

    SCAN_DURATION=$(( $(date +%s) - start_epoch ))
    local scan_rate=0
    (( SCAN_DURATION > 0 )) && scan_rate=$(echo "scale=1; $TOTAL_SCANNED / $SCAN_DURATION" | bc 2>/dev/null || echo "?")
    local total_ports_tested=$(( TOTAL_SCANNED * (${#REMOTE_ACCESS_PORTS[@]} + ${#OT_PROTOCOL_PORTS[@]}) ))
    local total_findings=${#FINDINGS_ALL[@]}

    clear
    show_header "WUP WUP - Scan Complete"

    cl "$WHITE" "SCAN STATISTICS:"
    printf "${GRAY}  ┌────────────────────────────────────────────────────┐${RESET}\n"
    printf "${WHITE}  │ Total IPs Scanned:    %-30s│${RESET}\n" "$TOTAL_SCANNED"
    printf "${WHITE}  │ Total Ports Tested:   %-30s│${RESET}\n" "$total_ports_tested"
    printf "${WHITE}  │ Scan Duration:        %-30s│${RESET}\n" "${SCAN_DURATION} seconds"
    printf "${WHITE}  │ Average Rate:         %-30s│${RESET}\n" "${scan_rate} IPs/second"
    printf "${GRAY}  └────────────────────────────────────────────────────┘${RESET}\n"
    echo ""

    local findings_color="$GREEN"
    (( total_findings > 0 )) && findings_color="$RED"
    cl "$WHITE" "FINDINGS SUMMARY:"
    printf "${GRAY}  ┌────────────────────────────────────────────────────┐${RESET}\n"
    local critical_color="$WHITE"; (( CRITICAL_COUNT > 0 )) && critical_color="$RED"
    local high_color="$WHITE"; (( HIGH_COUNT > 0 )) && high_color="$YELLOW"
    printf "${critical_color}  │ Critical:   %-38s│${RESET}\n" "$CRITICAL_COUNT"
    printf "${high_color}  │ High:       %-38s│${RESET}\n" "$HIGH_COUNT"
    printf "${findings_color}  │ Total:      %-38s│${RESET}\n" "$total_findings"
    printf "${GRAY}  └────────────────────────────────────────────────────┘${RESET}\n"
    echo ""

    if (( total_findings > 0 )); then
        cl "$RED" "[!] IMMEDIATE ACTIONS REQUIRED:"
        echo ""
        cl "$YELLOW" "  1. Disconnect CRITICAL devices from internet IMMEDIATELY"
        cl "$YELLOW" "  2. Implement VPN for all remote access (RDP/VNC/SSH)"
        cl "$YELLOW" "  3. Change ALL default passwords on PLCs/HMIs"
        cl "$YELLOW" "  4. Restrict OT protocols to engineering VLAN only"
        cl "$YELLOW" "  5. Check for cellular modem exposure (CISA blind spot)"
        cl "$YELLOW" "  6. Document findings and report to CISA if compromised"
        echo ""
        cl "$GRAY" "  Reference: CISA Alert AA26-097A (2026-07-30)"
        cl "$GRAY" "  Report: https://www.cisa.gov/report-cyber-incident"
        cl "$GRAY" "  CISA Scanning: https://www.cisa.gov/cyber-hygiene-services"
    else
        cl "$GREEN" "[✓] No internet-exposed threats detected."
        cl "$GRAY"  "  Continue monitoring and maintain security controls."
    fi

    if $EXPORT_REPORT; then
        echo ""
        cl "$CYAN" "Generating report..."
        local report_path
        report_path=$(generate_report)
        if [[ -n "$report_path" ]]; then
            printf "${GREEN}[✓] Report saved to: %s${RESET}\n" "$report_path"
            cl "$GRAY"  "  Share this report with your IT team or management."
        fi
    fi

    echo ""
    printf "${YELLOW}Press Enter to exit...${RESET}"
    read -r _
}

# Only run main when executed directly, not when sourced (enables unit testing)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
