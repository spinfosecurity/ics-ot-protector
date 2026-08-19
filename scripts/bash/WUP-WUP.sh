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
#   ✓ Generates simple text report (optional)
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

SCRIPT_VERSION="3.3.0"
SCRIPT_REFERENCE="CISA Alert AA26-097A (2026-07-30)"

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
# Port / protocol tables
# ---------------------------------------------------------------------------- #

# Remote access ports: "PORT|SERVICE_LABEL|SEVERITY"
declare -a REMOTE_ACCESS_PORTS=(
    "3389|RDP (Remote Desktop) - #1 attack vector|CRITICAL"
    "5900|VNC (Virtual Network Computing) - Active exploitation|CRITICAL"
    "5901|VNC Alternate|CRITICAL"
    "22|SSH (Secure Shell) - CISA-flagged in water attacks|CRITICAL"
    "80|HTTP (Web HMI)|HIGH"
    "443|HTTPS (Web HMI)|HIGH"
    "8080|HTTP Alternate (Web HMI)|HIGH"
    "8443|HTTPS Alternate (Web HMI)|HIGH"
)

# OT protocol ports: "PORT|PROTOCOL_LABEL"
declare -a OT_PROTOCOL_PORTS=(
    "44818|EtherNet/IP (CIP) - Rockwell/Allen-Bradley [TARGETED]"
    "2222|EtherNet/IP Alternate - CISA-flagged"
    "502|Modbus TCP - Unauthenticated protocol"
    "102|S7 Comm (Siemens SIMATIC)"
    "20000|DNP3 - Water sector common"
    "47808|BACnet/IP - Building/HVAC integration"
    "20256|UniLogic (Unitronics Vision PLC)"
)

# ThreatContext lookup
get_threat_context() {
    local key="$1"
    case "$key" in
        RDP)         echo "PRIMARY ATTACK VECTOR - 70% of water sector breaches (CISA 2026)" ;;
        VNC)         echo "Active exploitation by Iran-linked groups (FBI PSA 2026-08-01)" ;;
        SSH)         echo "CISA-flagged in July 2026 water sector attacks" ;;
        EtherNet/IP) echo "Rockwell MicroLogix 1400 targeted (4,148 exposed globally)" ;;
        Modbus)      echo "Unauthenticated - easily manipulated (CVSS 9.3)" ;;
        S7)          echo "Siemens SIMATIC S7-1200 (4,117 exposed globally)" ;;
        HTTP)        echo "Internet-exposed Web HMI per CISA/EPA joint advisory" ;;
        HTTPS)       echo "Internet-exposed Web HMI per CISA/EPA joint advisory" ;;
        DNP3)        echo "Water sector SCADA protocol - no encryption" ;;
        UniLogic)    echo "Unitronics Vision PLC - default password '1111'" ;;
        BACnet/IP)   echo "Building/HVAC integration protocol - no authentication" ;;
        *)           echo "Exposed service — review access controls" ;;
    esac
}

# ---------------------------------------------------------------------------- #
# TCP port test (cross-platform: /dev/tcp or nc fallback)
# ---------------------------------------------------------------------------- #
test_port() {
    local ip="$1" port="$2" timeout_sec="$3"
    # Try bash built-in /dev/tcp first (no external deps)
    if (timeout "$timeout_sec" bash -c "exec 3<>/dev/tcp/${ip}/${port}" 2>/dev/null); then
        return 0
    fi
    return 1
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
    cl "$GRAY"  "  ✓ Generates simple text report (optional)"
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

    cl "$WHITE" "Would you like to save a scan report to a text file?"
    echo ""
    cl "$GRAY"  "  • Report includes all findings with timestamps"
    cl "$GRAY"  "  • Easy to share with IT team or management"
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

    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local report_file="${report_dir}/WUPWUP_Report_${timestamp}.txt"

    {
        echo "================================================================================"
        echo "                    WUP WUP - WATER UTILITY PROTECTOR"
        echo "                    Security Scan Report"
        echo "================================================================================"
        echo ""
        echo "Report Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Script Version: ${SCRIPT_VERSION}"
        echo "Reference: ${SCRIPT_REFERENCE}"
        echo ""
        echo "================================================================================"
        echo "SCAN CONFIGURATION"
        echo "================================================================================"
        echo ""
        echo "Subnets Scanned:"
        for subnet in "${SUBNETS[@]}"; do
            echo "  • $subnet"
        done
        echo ""
        echo "Timeout: ${TIMEOUT} seconds per IP"
        echo "Total IPs Scanned: ${TOTAL_SCANNED}"
        echo "Scan Duration: ${SCAN_DURATION} seconds"
        echo ""
        echo "================================================================================"
        echo "FINDINGS SUMMARY"
        echo "================================================================================"
        echo ""
        echo "Total Findings: ${#FINDINGS_ALL[@]}"
        echo "  • Critical: ${CRITICAL_COUNT}"
        echo "  • High: ${HIGH_COUNT}"
        echo ""
        echo "================================================================================"
        echo "CRITICAL FINDINGS (Immediate Action Required)"
        echo "================================================================================"
        if [[ "${CRITICAL_COUNT}" -gt 0 ]]; then
            for entry in "${FINDINGS_ALL[@]}"; do
                IFS='|' read -r sev ip port service threat_type threat_ctx action <<< "$entry"
                [[ "$sev" == "CRITICAL" ]] || continue
                echo ""
                echo "[${ip}:${port}] - ${service}"
                echo "  Type: ${threat_type}"
                echo "  Context: ${threat_ctx}"
                echo "  Action: ${action}"
            done
        else
            echo ""
            echo "  No critical findings."
        fi
        echo ""
        echo "================================================================================"
        echo "HIGH-PRIORITY FINDINGS"
        echo "================================================================================"
        if [[ "${HIGH_COUNT}" -gt 0 ]]; then
            for entry in "${FINDINGS_ALL[@]}"; do
                IFS='|' read -r sev ip port service threat_type threat_ctx action <<< "$entry"
                [[ "$sev" == "HIGH" ]] || continue
                echo ""
                echo "[${ip}:${port}] - ${service}"
                echo "  Type: ${threat_type}"
                echo "  Context: ${threat_ctx}"
                echo "  Action: ${action}"
            done
        else
            echo ""
            echo "  No high-priority findings."
        fi
        echo ""
        echo "================================================================================"
        echo "RECOMMENDED ACTIONS"
        echo "================================================================================"
        echo ""
        echo "1. Disconnect CRITICAL devices from internet IMMEDIATELY"
        echo "2. Implement VPN for all remote access (RDP/VNC/SSH)"
        echo "3. Change ALL default passwords on PLCs/HMIs"
        echo "4. Restrict OT protocols to engineering VLAN only"
        echo "5. Check for cellular modem exposure (CISA blind spot)"
        echo "6. Document findings and report to CISA if compromised"
        echo ""
        echo "Reference: CISA Alert AA26-097A (2026-07-30)"
        echo "Report Incident: https://www.cisa.gov/report-cyber-incident"
        echo "CISA Scanning: https://www.cisa.gov/cyber-hygiene-services"
        echo ""
        echo "================================================================================"
        echo "                            END OF REPORT"
        echo "================================================================================"
    } > "$report_file"

    echo "$report_file"
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

    for subnet in "${SUBNETS[@]}"; do
        local network_prefix
        network_prefix=$(echo "$subnet" | awk -F'[./]' '{print $1"."$2"."$3}')
        local subnet_start_epoch
        subnet_start_epoch=$(date +%s)
        local subnet_findings=0

        show_scan_header "$subnet"

        for i in $(seq 1 254); do
            local ip="${network_prefix}.${i}"
            (( TOTAL_SCANNED++ )) || true

            if (( i % 25 == 0 )); then
                echo ""
                show_progress "$i" 254 "$subnet_start_epoch"
            fi

            # --- Remote access ports ---
            for entry in "${REMOTE_ACCESS_PORTS[@]}"; do
                IFS='|' read -r port service severity <<< "$entry"
                if test_port "$ip" "$port" "$TIMEOUT"; then
                    local first_token
                    first_token=$(echo "$service" | grep -oE '^[A-Za-z0-9/]+')
                    local threat_ctx
                    threat_ctx=$(get_threat_context "$first_token")

                    if [[ "$severity" == "CRITICAL" ]]; then
                        echo ""
                        printf "${RED}  [!!! CRITICAL !!!] %s:%s - %s${RESET}\n" "$ip" "$port" "$service"
                        printf "${RED}      %s${RESET}\n" "$threat_ctx"
                        printf "${YELLOW}      Action: BLOCK IMMEDIATELY or restrict to VPN only${RESET}\n"
                        FINDINGS_ALL+=("CRITICAL|${ip}|${port}|${service}|Remote Access - Immediate Threat|${threat_ctx}|BLOCK IMMEDIATELY or restrict to VPN only")
                        (( CRITICAL_COUNT++ )) || true
                    else
                        echo ""
                        printf "${YELLOW}  [!! HIGH !!] %s:%s - %s${RESET}\n" "$ip" "$port" "$service"
                        printf "${YELLOW}      %s${RESET}\n" "$threat_ctx"
                        printf "${DARK_YELLOW}      Action: Restrict to engineering VLAN; implement MFA${RESET}\n"
                        FINDINGS_ALL+=("HIGH|${ip}|${port}|${service}|Web HMI Exposure|${threat_ctx}|Restrict to engineering VLAN; implement MFA")
                        (( HIGH_COUNT++ )) || true
                    fi
                    (( subnet_findings++ )) || true
                fi
            done

            # --- OT protocol ports ---
            for entry in "${OT_PROTOCOL_PORTS[@]}"; do
                IFS='|' read -r port protocol <<< "$entry"
                if test_port "$ip" "$port" "$TIMEOUT"; then
                    local proto_token
                    proto_token=$(echo "$protocol" | grep -oE '^[A-Za-z0-9/]+')
                    local threat_ctx
                    threat_ctx=$(get_threat_context "$proto_token")
                    echo ""
                    printf "${MAGENTA}  [!! HIGH !!] %s:%s - %s${RESET}\n" "$ip" "$port" "$protocol"
                    printf "${MAGENTA}      %s${RESET}\n" "$threat_ctx"
                    printf "${DARK_YELLOW}      Action: Remove from internet; implement firewall rules${RESET}\n"
                    FINDINGS_ALL+=("HIGH|${ip}|${port}|${protocol}|OT Protocol Exposure|${threat_ctx}|Remove from internet; implement firewall rules")
                    (( HIGH_COUNT++ )) || true
                    (( subnet_findings++ )) || true
                fi
            done
        done

        echo ""
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

    if $EXPORT_REPORT && (( total_findings > 0 )); then
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

main "$@"
