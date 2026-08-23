#!/usr/bin/env bash
# =============================================================================
# Energy Grid Protector (EGP) v1.1.0
# OT/SCADA Cybersecurity Scanner - Power Grid Edition
# Author  : spinfosecurity
# License : MIT
# Project : https://github.com/spinfosecurity/ics-ot-protector/tree/main/scanners/energy-grid
# Ref     : CISA Alert AA26-097A | FBI PSA 2026-08-01
#
# USAGE:
#   ./EGP.sh -s <subnet/24> [-t <timeout_sec>] [-c] [-o <output_dir>]
#
# OPTIONS:
#   -s  Target /24 CIDR subnet (required), e.g. 192.168.10.0/24
#   -t  TCP connection timeout in seconds (default: 1, range: 1-10)
#   -c  CVE-only fast-scan mode (skip remote-access and ICS protocol checks)
#   -o  Output directory for report (default: ./reports)
#   -h  Show this help message
#
# EXAMPLES:
#   ./EGP.sh -s 10.10.20.0/24
#   ./EGP.sh -s 192.168.100.0/24 -t 2 -c
#   ./EGP.sh -s 172.16.5.0/24 -o /var/log/egp
#
# USE ONLY ON NETWORKS YOU OWN OR HAVE EXPLICIT WRITTEN AUTHORIZATION TO SCAN.
# =============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../_shared/load_sector_config.sh
source "${REPO_ROOT}/scanners/_shared/load_sector_config.sh"
# shellcheck source=../_shared/scanner_helpers.sh
source "${REPO_ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=../_shared/export_scan_report.sh
source "${REPO_ROOT}/scanners/_shared/export_scan_report.sh"
# shellcheck source=../_shared/scan_engine.sh
source "${REPO_ROOT}/scanners/_shared/scan_engine.sh"
initialize_energy_grid_config

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SUBNET=""
TIMEOUT=1
CVE_ONLY=false
OUTPUT_DIR="./reports"

# ---------------------------------------------------------------------------
# Color codes
# ---------------------------------------------------------------------------
RED='\033[0;31m'
DARK_RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    grep '^#' "$0" | grep -E '(USAGE|OPTIONS|EXAMPLES|  \-)' | sed 's/^# //'
    echo ""
    echo "Usage: $0 -s <subnet/24> [-t <timeout>] [-c] [-o <output_dir>]"
    exit 0
}

# ---------------------------------------------------------------------------
# Parse arguments (only when executed directly)
# ---------------------------------------------------------------------------
parse_args() {
while getopts ":s:t:o:ch" opt; do
    case $opt in
        s) SUBNET="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        c) CVE_ONLY=true ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) usage ;;
        :) echo "[-] Option -$OPTARG requires an argument." >&2; exit 1 ;;
        \?) echo "[-] Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done
}

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
validate_inputs() {
    if [[ -z "$SUBNET" ]]; then
        echo -e "${RED}[-] Error: Subnet (-s) is required.${NC}" >&2
        echo "    Example: $0 -s 192.168.10.0/24"
        exit 1
    fi

    # Validate /24 CIDR format
    if ! [[ "$SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/24$ ]]; then
        echo -e "${RED}[-] Error: Subnet must be a valid /24 CIDR (e.g., 192.168.1.0/24).${NC}" >&2
        exit 1
    fi

    # Validate each octet
    local base_ip
    base_ip="${SUBNET%/24}"
    IFS='.' read -r -a octets <<< "$base_ip"
    for octet in "${octets[@]}"; do
        if (( octet < 0 || octet > 255 )); then
            echo -e "${RED}[-] Error: Octet '$octet' out of valid range (0-255).${NC}" >&2
            exit 1
        fi
    done

    # Validate timeout
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || (( TIMEOUT < 1 || TIMEOUT > 10 )); then
        echo -e "${RED}[-] Error: Timeout must be an integer between 1 and 10 seconds.${NC}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# EGP-specific finding output (colored console + JSON export)
# ---------------------------------------------------------------------------
egp_finding_hook() {
    local ip="$1"
    local port="$2"
    local label="$3"
    local severity="$4"
    local category="$5"
    local description="$6"
    local remediation="$7"

    local color="$NC"
    case "$severity" in
        CRITICAL) color="$RED" ;;
        HIGH)     color="$DARK_RED" ;;
        MEDIUM)   color="$YELLOW" ;;
    esac

    echo ""
    echo -e "  ${color}[${severity}]${NC} ${WHITE}${ip}:${port}${NC} - ${color}${label}${NC}"
    echo -e "    ${GRAY}${description}${NC}"

    export_scan_report_append "$ip" "$port" "$label" "$severity" "$category" "$description" "$remediation"
}

egp_progress_hook() {
    local ip="$1"
    local processed="$2"
    local total="$3"
    local pct=$(( (processed * 100) / total ))
    printf "\r${CYAN}[*] Progress: [%-50s] %d%% | Host: %-16s${NC}" \
        "$(printf '#%.0s' $(seq 1 $((pct / 2))))" "$pct" "$ip"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
show_banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  Energy Grid Protector (EGP) v1.1.0"
    echo "  OT/SCADA Cybersecurity Scanner - Power Grid Edition"
    echo "  github.com/spinfosecurity/ics-ot-protector"
    echo -e "  Ref: CISA AA26-097A | FBI PSA 2026-08-01${NC}"
    echo -e "${YELLOW}  USE ONLY ON NETWORKS YOU ARE AUTHORIZED TO SCAN${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
run_egp_scan() {
parse_args "$@"
validate_inputs
show_banner

mkdir -p "$OUTPUT_DIR" || { echo "[-] Cannot create output directory: $OUTPUT_DIR" >&2; exit 1; }

if [[ "$CVE_ONLY" == true ]]; then
    MODE_LABEL="CVE-ONLY (fast-scan)"
else
    MODE_LABEL="FULL SCAN"
fi

EXTRA_META=$(jq -n \
  --arg version "1.1.0" \
  --arg scan_mode "$MODE_LABEL" \
  --arg target "$SUBNET" \
  --argjson timeout_ms $((TIMEOUT * 1000)) \
  --arg reference "CISA Alert AA26-097A | FBI PSA 2026-08-01" \
  '{version:$version, scan_mode:$scan_mode, target:$target, timeout_ms:$timeout_ms, reference:$reference}')

export_scan_report_init "$OUTPUT_DIR" "EGP-results" "energy-grid" "Energy Grid Protector" "$EXTRA_META"

echo -e "${CYAN}[*] Mode       : ${MODE_LABEL}${NC}"
echo -e "${CYAN}[*] Target     : ${SUBNET}${NC}"
echo -e "${CYAN}[*] Timeout    : ${TIMEOUT}s per port${NC}"
echo -e "${CYAN}[*] Output Dir : ${OUTPUT_DIR}${NC}"
echo ""

if [[ "$CVE_ONLY" == true ]]; then
  build_energy_grid_port_catalog cve_only
else
  build_energy_grid_port_catalog full
fi

build_scan_targets "$SUBNET"
SCAN_TARGETS=("${SCAN_TARGETS[@]}")
HOSTS_SCANNED=${#SCAN_TARGETS[@]}

SCAN_ENGINE_FINDING_HOOK=egp_finding_hook
SCAN_ENGINE_PROGRESS_HOOK=egp_progress_hook
run_tcp_port_scan 1 $((TIMEOUT * 1000))

FINDINGS=$SCAN_ENGINE_FINDINGS
echo ""

JSON_REPORT="$(export_scan_report_finalize)"

echo -e "${CYAN}============================================================${NC}"
echo -e "  ${GREEN}SCAN COMPLETE${NC}"
echo -e "  ${WHITE}Hosts Scanned : ${HOSTS_SCANNED}${NC}"
if (( FINDINGS > 0 )); then
    echo -e "  ${RED}Findings      : ${FINDINGS}${NC}"
else
    echo -e "  ${GREEN}Findings      : ${FINDINGS}${NC}"
fi
echo -e "  ${WHITE}Report Saved  : ${JSON_REPORT}${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
if (( FINDINGS > 0 )); then
    echo -e "${RED}[!] ACTION REQUIRED: Review findings and apply remediations.${NC}"
    echo -e "${YELLOW}    See docs/CISA-Reference.md and docs/Threat-Intelligence.md${NC}"
fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  run_egp_scan "$@"
fi
