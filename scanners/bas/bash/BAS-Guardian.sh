#!/bin/bash

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../_shared/load_sector_config.sh
source "${REPO_ROOT}/scanners/_shared/load_sector_config.sh"
# shellcheck source=../_shared/scanner_helpers.sh
source "${REPO_ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=../_shared/export_scan_report.sh
source "${REPO_ROOT}/scanners/_shared/export_scan_report.sh"
# shellcheck source=../_shared/scan_engine.sh
source "${REPO_ROOT}/scanners/_shared/scan_engine.sh"
# shellcheck source=../_shared/preflight.sh
source "${REPO_ROOT}/scanners/_shared/preflight.sh"
initialize_bas_config

# =============================================================================
# BAS Guardian - Building Automation System Protector (Bash)
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DARK_GRAY='\033[0;90m'
NC='\033[0m'

test_port() {
    test_tcp_port "$1" "$2" "$3"
}

bas_finding_hook() {
    local ip="$1" port="$2" service="$3" severity="$4" _category="$5" description="$6" remediation="$7"
    findings+=("$ip|$port|$service|$severity|$description|$remediation")

    if [[ "$service" == *"BMS Platform"* ]]; then
        echo -e "  ${RED}[!!! VENDOR CRITICAL !!!] $ip:$port - ${service% BMS Platform}${NC}"
        echo -e "      ${RED}$description${NC}"
        critical_count=$((critical_count + 1))
    elif [[ "$severity" == "CRITICAL" ]]; then
        echo -e "  ${RED}[CRITICAL] $ip:$port - $service${NC}"
        echo -e "      ${RED}$description${NC}"
        critical_count=$((critical_count + 1))
    elif [[ "$service" == *"BACnet"* || "$service" == *"LonWorks"* || "$service" == *"Tridium"* ]]; then
        echo -e "  ${MAGENTA}[BAS] $ip:$port - $service${NC}"
        high_count=$((high_count + 1))
    else
        echo -e "  ${YELLOW}[HIGH] $ip:$port - $service${NC}"
        if [[ "$port" == "80" ]]; then
            echo -e "      ${YELLOW}${THREAT_CONTEXT[Honeywell]}${NC}"
        else
            echo -e "      ${YELLOW}$description${NC}"
        fi
        high_count=$((high_count + 1))
    fi
}

bas_progress_hook() {
    local _host="$1" processed="$2" total="$3"
    if (( processed % 50 == 0 )); then
        echo -e "${DARK_GRAY}  Progress: ${processed}/${total}${NC}"
    fi
}

show_intro() {
    clear
    echo -e "${CYAN}================================================================================${NC}"
    echo -e "${WHITE}                    BAS GUARDIAN v2.0${NC}"
    echo -e "${WHITE}                    $SCRIPT_TAGLINE${NC}"
    echo -e "${CYAN}================================================================================${NC}"
    echo ""
    echo "Version: $SCRIPT_VERSION | Updated: August 2026"
    echo "Reference: $REFERENCE"
    echo ""
    echo -e "${CYAN}================================================================================${NC}"
    echo ""
    echo -e "${GREEN}NEW in v2.0 - Vendor-Specific Intelligence:${NC}"
    echo "  + Honeywell IQ4x (CVE-2026-3611, CVSS 10.0) - auth disabled by default"
    echo "  + Johnson Controls C-CURE 9000/Victor (ICSA-26-204-01) - RCE risk"
    echo "  + Siemens Desigo CC/SENTRON Powermanager - privilege escalation"
    echo "  + Tridium Niagara Framework port exposure (candidate)"
    echo ""
    echo "What This Does:"
    echo "  + Scans building automation subnets for exposed BACnet devices"
    echo "  + Detects RDP (3389), VNC (5900), SSH (22) on BMS workstations"
    echo "  + Identifies BACnet/IP (47808), BACnet/SC (4800), LonWorks (1628) exposure"
    echo "  + Fingerprints vendor-specific BMS platforms (Honeywell, JCI, Siemens, Tridium)"
    echo "  + Flags unauthenticated BACnet traffic vulnerable to CVE-2026-24060"
    echo "  + Prioritizes findings by severity (CRITICAL vs HIGH)"
    echo "  + Generates JSON scan report (optional)"
    echo ""
    echo "What This Does NOT Do:"
    echo "  - Does NOT test credentials or attempt authentication"
    echo "  - Does NOT modify HVAC/BMS configurations"
    echo "  - Does NOT replace professional penetration testing"
    echo "  - Does NOT decrypt BACnet/SC traffic"
    echo "  - Does NOT work over IPv6 (IPv4 only)"
    echo "  - Does NOT scan non-/24 subnets"
    echo ""
    echo -e "${YELLOW}AUTHORIZED USE ONLY:${NC}"
    echo "  This tool is for defensive security assessment by authorized personnel only."
    echo "  Only scan networks you own or have explicit written permission to test."
    echo ""
    echo -e "${CYAN}================================================================================${NC}"
    echo ""
    echo -e "${YELLOW}Press Enter to begin configuration or Ctrl+C to exit...${NC}"
    read -r
}

show_header() {
    echo -e "\n${CYAN}============================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    [ -n "$2" ] && echo -e "${DARK_GRAY}  $2${NC}"
    echo -e "${CYAN}============================================${NC}\n"
}

ask_subnets() {
    clear
    show_header "Step 1: Configure Scan Targets"
    echo "Which building automation subnets would you like to scan?"
    echo "  - Enter up to 5 subnets in format: 192.168.20.0/24"
    echo "  - Press Enter on empty line to finish"
    echo ""

    subnets=()
    local count=0

    while [ $count -lt 5 ]; do
        count=$((count + 1))
        read -rp "  Subnet #$count: " subnet
        [ -z "$subnet" ] && break

        if [[ $subnet =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            prefix_length=$(echo "$subnet" | cut -d'/' -f2)
            if [ "$prefix_length" -eq 24 ]; then
                subnets+=("$subnet")
                echo -e "  ${GREEN}Added: $subnet${NC}"
            else
                echo -e "  ${RED}Only /24 subnets are supported${NC}"
            fi
        else
            echo -e "  ${RED}Invalid format. Use: 192.168.20.0/24${NC}"
        fi
    done

    if [ ${#subnets[@]} -eq 0 ]; then
        echo -e "\n  ${RED}No subnets entered. Exiting...${NC}"
        exit 1
    fi
}

ask_timeout() {
    clear
    show_header "Step 2: Set Scan Timeout"
    echo "Connection timeout per IP (in seconds):"
    echo "  1 second    = Fast, may miss slow devices"
    echo "  2 seconds   = Balanced (recommended)"
    echo "  3-5 seconds = Slower but more thorough"
    echo ""

    while true; do
        read -rp "  Enter timeout (1-30, default 2): " timeout_input
        if [ -z "$timeout_input" ]; then
            timeout=2
            break
        elif [[ $timeout_input =~ ^[0-9]+$ ]] && [ "$timeout_input" -ge 1 ] && [ "$timeout_input" -le 30 ]; then
            timeout=$timeout_input
            break
        else
            echo -e "  ${RED}Enter a number between 1 and 30${NC}"
        fi
    done
}

ask_export_report() {
    clear
    show_header "Step 3: Export Options"
    read -rp "  Save scan report to file? (Y/N): " answer
    [[ $answer =~ ^[Yy]$ ]] && export_report=true || export_report=false
}

confirm_scan() {
    clear
    show_header "Step 4: Confirm Configuration"
    echo "Subnets to scan:"
    for s in "${subnets[@]}"; do echo "  - $s"; done
    echo ""
    echo "Timeout: ${timeout}s per IP"
    echo "Total IPs: $(( ${#subnets[@]} * 254 ))"
    echo "Report export: $([ "$export_report" = true ] && echo Yes || echo No)"
    echo ""
    read -rp "Start scan? (Y/N): " confirm
    [[ $confirm =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }

    local subnets_csv
    subnets_csv=$(IFS=,; echo "${subnets[*]}")
    preflight_check_dependencies
    preflight_validate_scan_scope "$subnets_csv" 0
    build_bas_port_catalog
    preflight_print_summary "bas" "${#PORTS[@]}" 50 "$((timeout * 1000))"
}

generate_report() {
    local report_dir="./reports"
    mkdir -p "$report_dir"

    if ! command -v jq >/dev/null 2>&1; then
        echo "generate_report requires jq" >&2
        return 1
    fi

    local findings_json='[]'
    for f in "${findings[@]}"; do
        IFS='|' read -r ip port service severity tctx action <<< "$f"
        findings_json=$(jq -n \
            --argjson arr "$findings_json" \
            --arg ts "$(date '+%Y-%m-%dT%H:%M:%S')" \
            --arg host "$ip" \
            --argjson port "$port" \
            --arg service "$service" \
            --arg severity "$severity" \
            --arg category "BAS Exposure" \
            --arg description "$tctx" \
            --arg remediation "$action" \
            '$arr + [{Timestamp:$ts, Host:$host, Port:$port, Service:$service, Severity:$severity, Category:$category, Description:$description, Remediation:$remediation}]')
    done

    build_bas_port_catalog
    export_scan_report_write "$report_dir" "BAS-results" "bas" "BAS Guardian" "$findings_json" \
        "$total_scanned" "${#PORTS[@]}" "$((scan_duration * 1000))" 1
}

main() {
    show_intro
    ask_subnets
    ask_timeout
    ask_export_report
    confirm_scan

    clear
    show_header "BAS Guardian v2.0 - Starting Threat Detection" "Scanning for exposed building automation systems"
    echo "Subnets: ${subnets[*]}"
    echo "Timeout: ${timeout}s per IP"
    echo ""

    findings=()
    total_scanned=0
    critical_count=0
    high_count=0
    start_time=$(date +%s)

    build_bas_port_catalog
    SCAN_ENGINE_FINDING_HOOK=bas_finding_hook
    SCAN_ENGINE_PROGRESS_HOOK=scan_engine_default_progress_hook
    export SCAN_ENGINE_FINDING_HOOK SCAN_ENGINE_PROGRESS_HOOK

    for subnet in "${subnets[@]}"; do
        echo -e "\n${CYAN}[SCAN] $subnet${NC}"
        subnet_start=$(date +%s)
        subnet_findings_before=${#findings[@]}

        scan_engine_reset_progress
        build_scan_targets "$subnet"
        SCAN_TARGETS=("${SCAN_TARGETS[@]}")
        run_tcp_port_scan 50 $((timeout * 1000))

        total_scanned=$((total_scanned + ${#SCAN_TARGETS[@]}))
        subnet_findings=$(( ${#findings[@]} - subnet_findings_before ))
        echo -e "${GREEN}  [COMPLETE] $subnet_findings findings in $(( $(date +%s) - subnet_start ))s${NC}"
    done

    end_time=$(date +%s)
    scan_duration=$((end_time - start_time))

    clear
    show_header "BAS Guardian v2.0 - Scan Complete"
    echo "Total IPs Scanned: $total_scanned"
    echo "Scan Duration: ${scan_duration}s"
    echo ""
    echo -e "Critical: ${RED}$critical_count${NC}  |  High: ${YELLOW}$high_count${NC}  |  Total: ${#findings[@]}"
    echo ""

    if [ ${#findings[@]} -gt 0 ]; then
        echo -e "${RED}IMMEDIATE ACTIONS REQUIRED:${NC}"
        echo "1. Remove BACnet devices from direct internet exposure"
        echo "2. Implement VPN for all remote BMS/HVAC access (RDP/VNC/SSH)"
        echo "3. Segment BAS network from corporate IT network"
        echo "4. If Honeywell IQ4x detected: verify web HMI auth is ENABLED (CVE-2026-3611, CVSS 10.0)"
        echo "5. If Johnson Controls C-CURE 9000/Victor detected: patch immediately (ICSA-26-204-01)"
        echo "6. If Siemens Desigo CC detected: apply patch, review privilege assignments"
        echo "7. Patch bacnet-stack to 1.4.3+ and monitor CVE-2026-24060 advisories"
        echo "8. Report suspicious activity to CISA: https://www.cisa.gov/report-cyber-incident"

        if [ "$export_report" = true ]; then
            report_path=$(generate_report)
            echo -e "\n${GREEN}Report saved to: $report_path${NC}"
        fi
    else
        echo -e "${GREEN}No internet-exposed threats detected.${NC}"
    fi

    echo ""
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
