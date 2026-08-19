#!/usr/bin/env bash
# =============================================================================
# Rail-OT-Protector (ROP) — Bash Scanner
# Scans rail/transit OT subnets for CVE-2025-1727 (EOT/HOT), RailSafe legacy
# SCADA API, ICS protocols, and remote-access exposure.
#
# Copyright (c) 2026 spinfosecurity | MIT License
# References: CISA AA26-097A, FBI PSA 2026-08-01
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../_shared/load_sector_config.sh
source "${REPO_ROOT}/scanners/_shared/load_sector_config.sh"
# shellcheck source=../_shared/export_scan_report.sh
source "${REPO_ROOT}/scanners/_shared/export_scan_report.sh"
initialize_rail_config

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SUBNETS=""
TIMEOUT_MS=1500
THREADS=64
OUTPUT_DIR="./reports"
EOT_HOT_ONLY=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Rail-OT-Protector (ROP) — Bash Scanner

Usage:
  ./ROP.sh --subnets <CIDR[,CIDR...]> [OPTIONS]

Required:
  --subnets <CIDRs>     Comma-separated CIDR ranges (e.g. 10.10.20.0/24,10.10.30.0/24)

Optional:
  --timeout-ms <n>      TCP connect timeout in ms (100-10000, default 1500)
  --threads <n>         Max concurrent workers (1-512, default 64)
  --output-dir <dir>    Report output directory (default ./reports)
  --eot_hot_only        Fast mode: EOT/HOT ports only (CVE-2025-1727)
  --help                Show this message
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
[[ $# -eq 0 ]] && { usage; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --subnets)     SUBNETS="$2";     shift 2 ;;
    --timeout-ms)  TIMEOUT_MS="$2"; shift 2 ;;
    --threads)     THREADS="$2";     shift 2 ;;
    --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
    --eot_hot_only) EOT_HOT_ONLY=1; shift ;;
    --help|-h)     usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
[[ -n "$SUBNETS" ]] || { printf '[ERROR] --subnets is required\n' >&2; exit 1; }

[[ "$TIMEOUT_MS" =~ ^[0-9]+$ ]] && (( TIMEOUT_MS >= 100 && TIMEOUT_MS <= 10000 )) || {
  printf '[ERROR] --timeout-ms must be an integer between 100 and 10000\n' >&2; exit 1;
}

[[ "$THREADS" =~ ^[0-9]+$ ]] && (( THREADS >= 1 && THREADS <= 512 )) || {
  printf '[ERROR] --threads must be an integer between 1 and 512\n' >&2; exit 1;
}

mkdir -p "$OUTPUT_DIR"
export_scan_report_init "$OUTPUT_DIR" "ROP-results" "rail" "Rail-OT-Protector"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() {
  local level="$1"; shift
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

validate_cidr() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]
}

ip2int() {
  local a b c d; IFS=. read -r a b c d <<< "$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int2ip() {
  local n=$1
  printf '%d.%d.%d.%d\n' \
    $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) \
    $(( (n >>  8) & 255 )) $((  n        & 255 ))
}

expand_cidr() {
  local cidr="$1" ip prefix ip_int mask network size
  ip="${cidr%/*}"; prefix="${cidr#*/}"
  (( prefix >= 8 )) || { printf '[WARN] Skipping prefix /%s — too broad for safe scan\n' "$prefix" >&2; return; }
  ip_int=$(ip2int "$ip")
  if (( prefix == 32 )); then mask=4294967295
  else mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  fi
  network=$(( ip_int & mask ))
  size=$(( 1 << (32 - prefix) ))
  local first=$(( network + 1 )) last=$(( network + size - 2 ))
  for (( cur=first; cur<=last; cur++ )); do int2ip "$cur"; done
}

# ---------------------------------------------------------------------------
# Port catalog  format: port|name|severity|category|description
# ---------------------------------------------------------------------------
declare -a PORTS=()
build_port_catalog() {
  if [[ "$EOT_HOT_ONLY" -eq 1 ]]; then
    build_rail_port_catalog eothot
  else
    build_rail_port_catalog all
  fi
}

write_finding() {
  local host="$1" port="$2" service="$3" severity="$4" category="$5" description="$6"
  export_scan_report_append "$host" "$port" "$service" "$severity" "$category" "$description" ""
  printf '[%s] [%s] %s:%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$severity" "$host" "$port" "$description"
}
export -f write_finding log export_scan_report_append

# ---------------------------------------------------------------------------
# Per-host scan worker
# ---------------------------------------------------------------------------
scan_host() {
  local host="$1"
  shift
  local timeout_sec; timeout_sec=$(awk "BEGIN{printf \"%.3f\",$TIMEOUT_MS/1000}")

  # Re-import port catalog in subshell (exported as env var array string)
  local IFS=$'\n'
  for record in $PORT_CATALOG_STR; do
    [[ -z "$record" ]] && continue
    local port service severity category description
    IFS='|' read -r port service severity category description <<< "$record"
    if timeout "$timeout_sec" bash -c "exec 3>/dev/tcp/$host/$port" 2>/dev/null; then
      write_finding "$host" "$port" "$service" "$severity" "$category" "$description"
    fi
  done
}
export -f scan_host export_scan_report_append
export TIMEOUT_MS SCAN_REPORT_JSON_TMP SCAN_REPORT_LOCK_DIR

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------
declare -a UNIQUE_TARGETS=()
declare -A SEEN=()

IFS=',' read -r -a subnet_arr <<< "$SUBNETS"
for subnet in "${subnet_arr[@]}"; do
  subnet="${subnet// /}"
  validate_cidr "$subnet" || { log WARN "Invalid CIDR, skipping: $subnet"; continue; }
  while IFS= read -r ip; do
    [[ -z "${SEEN[$ip]+x}" ]] && { UNIQUE_TARGETS+=("$ip"); SEEN[$ip]=1; }
  done < <(expand_cidr "$subnet")
done

(( ${#UNIQUE_TARGETS[@]} > 0 )) || { log ERROR 'No valid targets generated — check --subnets input'; exit 1; }

build_port_catalog

# Export port catalog as newline-delimited string for subshell workers
PORT_CATALOG_STR="$(printf '%s\n' "${PORTS[@]}")"
export PORT_CATALOG_STR

log INFO "Scan starting | Targets: ${#UNIQUE_TARGETS[@]} | Ports: ${#PORTS[@]} | Threads: $THREADS | Timeout: ${TIMEOUT_MS}ms | EotHotOnly: $EOT_HOT_ONLY"

# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------
processed=0
total=${#UNIQUE_TARGETS[@]}

for host in "${UNIQUE_TARGETS[@]}"; do
  while (( $(jobs -pr | wc -l) >= THREADS )); do wait -n 2>/dev/null || true; done
  scan_host "$host" &
  processed=$(( processed + 1 ))
  printf '\rProgress: %d / %d hosts queued (%d%%)' "$processed" "$total" $(( processed * 100 / total ))
done
wait
printf '\n'

# ---------------------------------------------------------------------------
# Finalize report
# ---------------------------------------------------------------------------
JSON_PATH="$(export_scan_report_finalize)"
log INFO "Scan complete | Report: $JSON_PATH"
