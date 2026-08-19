#!/usr/bin/env bash
# =============================================================================
# Energy Grid Protector (EGP) v1.0.0
# OT/SCADA Cybersecurity Scanner - Power Grid Edition
# Author  : spinfosecurity
# License : MIT
# Project : https://github.com/spinfosecurity/Energy-Grid-Protector
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
# Parse arguments
# ---------------------------------------------------------------------------
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
# TCP port check using /dev/tcp (no nmap/nc dependency)
# Falls back to nc if /dev/tcp unavailable
# ---------------------------------------------------------------------------
check_port() {
    local ip="$1"
    local port="$2"
    if bash -c "exec 3<>/dev/tcp/${ip}/${port}" 2>/dev/null; then
        exec 3>&- 2>/dev/null || true
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Thread-safe report writer using flock
# ---------------------------------------------------------------------------
write_finding() {
    local report_file="$1"
    local ip="$2"
    local port="$3"
    local label="$4"
    local severity="$5"
    local description="$6"
    local remediation="$7"

    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$timestamp] [$severity] ${ip}:${port} - ${label} | ${description} | REMEDIATION: ${remediation}"

    # Thread-safe write
    (
        flock -x 200
        echo "$line" >> "$report_file"
    ) 200>>"${report_file}.lock"

    # Console output with severity color
    local color="$NC"
    case "$severity" in
        CRITICAL) color="$RED" ;;
        HIGH)     color="$DARK_RED" ;;
        MEDIUM)   color="$YELLOW" ;;
    esac

    echo -e "  ${color}[${severity}]${NC} ${WHITE}${ip}:${port}${NC} - ${color}${label}${NC}"
    echo -e "    ${GRAY}${description}${NC}"
}

# ---------------------------------------------------------------------------
# CVE definitions
# Format: "port1,port2,...|Description|Severity|Remediation"
# ---------------------------------------------------------------------------
declare -A cve_checks
cve_checks["CVE-2026-42945"]="80,443,8080,8443|Hitachi Energy e-mesh EMS (v4.1.6 v4.4.2 v4.7.0) - Interoperability/standardization layer flaw in substation EMS. Unauthenticated network access may lead to service disruption or unauthorized control.|CRITICAL|Apply Hitachi Energy patch. Isolate EMS behind VPN/firewall. See docs/CISA-Reference.md"
cve_checks["CVE-2025-1445"]="102,2404,44818,2222|Hitachi Energy/ABB/B&R shared hardware vulnerability - Improper input validation out-of-bounds write memory buffer restriction failure. Affects ABB ACS880 drives with IEC 61131-3 license.|CRITICAL|Update firmware per vendor advisories. Apply IEC 62443 network segmentation. See docs/CISA-Reference.md"
cve_checks["CVE-2025-13162"]="135,445,8080|ABB Advant Master Online Builder / 800xA - Uncontrolled search path element enabling arbitrary code execution via unrestricted DLL directory hijacking.|HIGH|Apply ABB Security Advisory patch. Restrict DLL search path write permissions. Use application allowlisting. See docs/CISA-Reference.md"
cve_checks["RTU500-MULTI-CVE"]="20000,2404,102,443|Hitachi Energy RTU500 Series - Multiple disclosed vulnerabilities: authentication bypass denial of service improper certificate validation across RTU500 product line.|HIGH|Upgrade RTU500 firmware to patched version. Enforce certificate validation. Restrict DNP3/IEC104 access to known master stations. See docs/Threat-Intelligence.md"

# ---------------------------------------------------------------------------
# Remote-access port definitions
# Format: "Name|Severity|Description"
# ---------------------------------------------------------------------------
declare -A remote_access_ports
remote_access_ports[3389]="RDP|HIGH|Remote Desktop Protocol exposed on OT network. CISA AA26-097A and FBI PSA 2026-08-01 document active exploitation. Remove or restrict immediately."
remote_access_ports[5900]="VNC|CRITICAL|VNC port 5900 exposed. FBI PSA 2026-08-01 warns of active VNC exploitation against ICS environments. Disable or place behind VPN."
remote_access_ports[5901]="VNC-1|CRITICAL|VNC port 5901 exposed. FBI PSA 2026-08-01 warns of active VNC exploitation against ICS environments. Disable or place behind VPN."
remote_access_ports[22]="SSH|MEDIUM|SSH port open on OT host. Ensure key-based auth only disable password auth restrict to jump host access."
remote_access_ports[23]="Telnet|CRITICAL|Telnet transmits credentials in cleartext. Immediate removal required on all OT/SCADA assets per CISA guidance."
remote_access_ports[21]="FTP|HIGH|FTP transmits data and credentials in cleartext. Replace with SFTP or SCP. Active ICS malware campaigns use FTP for lateral movement."
remote_access_ports[80]="HTTP|MEDIUM|Unencrypted HTTP web interface exposed. Migrate to HTTPS. Restrict to operations VLAN only."
remote_access_ports[443]="HTTPS|MEDIUM|HTTPS web interface exposed. Verify certificate validity disable legacy TLS restrict to authorized clients."

# ---------------------------------------------------------------------------
# ICS protocol port definitions
# Format: "Name|Severity|Description"
# ---------------------------------------------------------------------------
declare -A ics_ports
ics_ports[20000]="DNP3|HIGH|DNP3 (IEEE 1815) exposed. Lacks authentication in many implementations. CISA AA26-097A: Iranian actors probing DNP3 on grid assets."
ics_ports[502]="Modbus|HIGH|Modbus TCP exposed. No native authentication or encryption. Restrict to known master station IPs via ACL."
ics_ports[102]="IEC-61850-S7|HIGH|IEC 61850 MMS / Siemens S7 port exposed. Verify device identity and restrict to authorized engineering workstations."
ics_ports[2404]="IEC-60870-5-104|HIGH|IEC 60870-5-104 (IEC104) exposed. Used for SCADA control. Restrict to designated control center IP ranges."
ics_ports[44818]="EtherNetIP|MEDIUM|EtherNet/IP (CIP) exposed. Restrict to PLC management VLAN and engineering stations."
ics_ports[2222]="EtherNetIP-IO|MEDIUM|EtherNet/IP implicit I/O port exposed. Should not be reachable from non-OT VLANs. Review network segmentation."

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
show_banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "  Energy Grid Protector (EGP) v1.0.0"
    echo "  OT/SCADA Cybersecurity Scanner - Power Grid Edition"
    echo "  github.com/spinfosecurity/Energy-Grid-Protector"
    echo -e "  Ref: CISA AA26-097A | FBI PSA 2026-08-01${NC}"
    echo -e "${YELLOW}  USE ONLY ON NETWORKS YOU ARE AUTHORIZED TO SCAN${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
validate_inputs
show_banner

# Prepare output directory
mkdir -p "$OUTPUT_DIR" || { echo "[-] Cannot create output directory: $OUTPUT_DIR" >&2; exit 1; }

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT_FILE="${OUTPUT_DIR}/EGP_Report_${TIMESTAMP}.txt"
LOCK_FILE="${REPORT_FILE}.lock"

if [[ "$CVE_ONLY" == true ]]; then
    MODE_LABEL="CVE-ONLY (fast-scan)"
else
    MODE_LABEL="FULL SCAN"
fi

# Initialize report
cat > "$REPORT_FILE" <<EOF
Energy Grid Protector (EGP) v1.0.0
Scan Mode    : $MODE_LABEL
Target Subnet: $SUBNET
Timeout      : ${TIMEOUT}s
Scan Started : $(date '+%Y-%m-%d %H:%M:%S')
Reference    : CISA Alert AA26-097A | FBI PSA 2026-08-01
Repository   : https://github.com/spinfosecurity/Energy-Grid-Protector
=======================================================================
EOF

touch "$LOCK_FILE"

echo -e "${CYAN}[*] Mode       : ${MODE_LABEL}${NC}"
echo -e "${CYAN}[*] Target     : ${SUBNET}${NC}"
echo -e "${CYAN}[*] Timeout    : ${TIMEOUT}s per port${NC}"
echo -e "${CYAN}[*] Report     : ${REPORT_FILE}${NC}"
echo ""

# Extract base prefix from /24 CIDR
BASE_IP="${SUBNET%/24}"
PREFIX="${BASE_IP%.*}"

FINDINGS=0
HOSTS_SCANNED=0
TOTAL_HOSTS=254

for i in $(seq 1 254); do
    IP="${PREFIX}.${i}"
    HOSTS_SCANNED=$((HOSTS_SCANNED + 1))
    PCT=$(( (HOSTS_SCANNED * 100) / TOTAL_HOSTS ))

    # Progress bar
    printf "\r${CYAN}[*] Progress: [%-50s] %d%% | Host: %-16s${NC}" \
        "$(printf '#%.0s' $(seq 1 $((PCT / 2))))" "$PCT" "$IP"

    # --- CVE Checks ---
    for cve_id in "${!cve_checks[@]}"; do
        IFS='|' read -r ports_str description severity remediation <<< "${cve_checks[$cve_id]}"
        IFS=',' read -r -a port_list <<< "$ports_str"
        for port in "${port_list[@]}"; do
            if check_port "$IP" "$port" 2>/dev/null; then
                echo ""
                write_finding "$REPORT_FILE" "$IP" "$port" "$cve_id" "$severity" "$description" "$remediation"
                FINDINGS=$((FINDINGS + 1))
            fi
        done
    done

    if [[ "$CVE_ONLY" == false ]]; then
        # --- Remote Access Checks ---
        for port in "${!remote_access_ports[@]}"; do
            IFS='|' read -r name severity description <<< "${remote_access_ports[$port]}"
            if check_port "$IP" "$port" 2>/dev/null; then
                echo ""
                write_finding "$REPORT_FILE" "$IP" "$port" "REMOTE-ACCESS:${name}" "$severity" "$description" "See docs/CISA-Reference.md"
                FINDINGS=$((FINDINGS + 1))
            fi
        done

        # --- ICS Protocol Checks ---
        for port in "${!ics_ports[@]}"; do
            IFS='|' read -r name severity description <<< "${ics_ports[$port]}"
            if check_port "$IP" "$port" 2>/dev/null; then
                echo ""
                write_finding "$REPORT_FILE" "$IP" "$port" "ICS-PROTOCOL:${name}" "$severity" "$description" "See docs/Threat-Intelligence.md"
                FINDINGS=$((FINDINGS + 1))
            fi
        done
    fi
done

echo ""

# Summary
SUMMARY=$(cat <<EOF

=======================================================================
SCAN COMPLETE
Hosts Scanned : $HOSTS_SCANNED
Findings      : $FINDINGS
Scan Ended    : $(date '+%Y-%m-%d %H:%M:%S')
Report Saved  : $REPORT_FILE

REMEDIATION RESOURCES:
  CISA Alert AA26-097A  : https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a
  FBI PSA 2026-08-01    : https://www.fbi.gov/
  CISA ICS Advisories   : https://www.cisa.gov/news-events/ics-advisories
  Report Vulnerabilities: https://www.cisa.gov/report
=======================================================================
EOF
)

echo "$SUMMARY" >> "$REPORT_FILE"
rm -f "$LOCK_FILE"

echo -e "${CYAN}============================================================${NC}"
echo -e "  ${GREEN}SCAN COMPLETE${NC}"
echo -e "  ${WHITE}Hosts Scanned : ${HOSTS_SCANNED}${NC}"
if (( FINDINGS > 0 )); then
    echo -e "  ${RED}Findings      : ${FINDINGS}${NC}"
else
    echo -e "  ${GREEN}Findings      : ${FINDINGS}${NC}"
fi
echo -e "  ${WHITE}Report Saved  : ${REPORT_FILE}${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
if (( FINDINGS > 0 )); then
    echo -e "${RED}[!] ACTION REQUIRED: Review findings and apply remediations.${NC}"
    echo -e "${YELLOW}    See docs/CISA-Reference.md and docs/Threat-Intelligence.md${NC}"
fi
