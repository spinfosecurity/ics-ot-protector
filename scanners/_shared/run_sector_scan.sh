#!/usr/bin/env bash
# Non-interactive sector scan runner for ICS OT Protector.
# Usage:
#   run_sector_scan.sh --sector <water|energy-grid|bas|rail> --subnets <CIDR[,CIDR...]> [options]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=load_sector_config.sh
source "${REPO_ROOT}/scanners/_shared/load_sector_config.sh"
# shellcheck source=scanner_helpers.sh
source "${REPO_ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=preflight.sh
source "${REPO_ROOT}/scanners/_shared/preflight.sh"
# shellcheck source=export_scan_report.sh
source "${REPO_ROOT}/scanners/_shared/export_scan_report.sh"
# shellcheck source=scan_engine.sh
source "${REPO_ROOT}/scanners/_shared/scan_engine.sh"

SECTOR=""
SUBNETS=""
THREADS=64
TIMEOUT_MS=1500
OUTPUT_DIR="./reports"
CVE_ONLY=0
EOT_HOT_ONLY=0
FORCE_LARGE=0
EXPORT_CSV=1
CONFIG_OVERLAY=""
QUIET=0

usage() {
  cat <<'EOF'
ICS OT Protector — non-interactive sector scan

Usage:
  run_sector_scan.sh --sector <name> --subnets <CIDR[,CIDR...]> [options]

Required:
  --sector <name>       water | energy-grid | bas | rail
  --subnets <CIDRs>     Comma-separated target ranges (e.g. 192.168.10.0/24,10.0.1.0/24)

Optional:
  --config <path>       YAML/JSON overlay merged onto the sector config
  --threads <n>         Concurrent workers (1-512, default 64)
  --timeout-ms <n>      TCP timeout in ms (100-10000, default 1500)
  --output-dir <dir>    Report directory (default ./reports)
  --cve-only            Energy-grid fast mode: CVE checks only
  --eot-hot-only        Rail fast mode: EOT/HOT ports only
  --force               Acknowledge large scan scope (/17-/8 or >4096 hosts)
  --no-csv              Skip CSV export (JSON is always written)
  --quiet               Suppress progress output
  --help                Show this message
EOF
}

log() {
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "${*:2}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sector)      SECTOR="$2";      shift 2 ;;
    --subnets)     SUBNETS="$2";     shift 2 ;;
    --config)      CONFIG_OVERLAY="$2"; shift 2 ;;
    --threads)     THREADS="$2";     shift 2 ;;
    --timeout-ms)  TIMEOUT_MS="$2";  shift 2 ;;
    --output-dir)  OUTPUT_DIR="$2";  shift 2 ;;
    --cve-only)    CVE_ONLY=1;       shift ;;
    --eot-hot-only) EOT_HOT_ONLY=1;  shift ;;
    --force)       FORCE_LARGE=1;    shift ;;
    --no-csv)      EXPORT_CSV=0;     shift ;;
    --quiet)       QUIET=1;          shift ;;
    --help|-h)     usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ -n "$SECTOR" ]] || { echo "Missing --sector" >&2; usage >&2; exit 1; }
[[ -n "$SUBNETS" ]] || { echo "Missing --subnets" >&2; usage >&2; exit 1; }

[[ "$TIMEOUT_MS" =~ ^[0-9]+$ ]] && (( TIMEOUT_MS >= 100 && TIMEOUT_MS <= 10000 )) || {
  echo "--timeout-ms must be an integer between 100 and 10000" >&2; exit 1;
}
[[ "$THREADS" =~ ^[0-9]+$ ]] && (( THREADS >= 1 && THREADS <= 512 )) || {
  echo "--threads must be an integer between 1 and 512" >&2; exit 1;
}

preflight_check_dependencies
preflight_validate_scan_scope "$SUBNETS" "$FORCE_LARGE"

if [[ -n "$CONFIG_OVERLAY" ]]; then
  export SECTOR_CONFIG_OVERLAY="$CONFIG_OVERLAY"
fi

case "$SECTOR" in
  water)
    initialize_water_config
    build_water_port_catalog
    REPORT_PREFIX="WUP-results"
    SCANNER_NAME="WUP WUP"
    ;;
  energy-grid)
    initialize_energy_grid_config
    if (( CVE_ONLY )); then
      build_energy_grid_port_catalog cve_only
    else
      build_energy_grid_port_catalog full
    fi
    REPORT_PREFIX="EGP-results"
    SCANNER_NAME="Energy Grid Protector"
    ;;
  bas)
    initialize_bas_config
    build_bas_port_catalog
    REPORT_PREFIX="BAS-results"
    SCANNER_NAME="BAS Guardian"
    ;;
  rail)
    initialize_rail_config
    if (( EOT_HOT_ONLY )); then
      build_rail_port_catalog eothot
    else
      build_rail_port_catalog all
    fi
    REPORT_PREFIX="ROP-results"
    SCANNER_NAME="Rail-OT-Protector"
    ;;
  *)
    echo "Unknown sector: $SECTOR" >&2
    exit 1
    ;;
esac

preflight_print_summary "$SECTOR" "${#PORTS[@]}" "$THREADS" "$TIMEOUT_MS"

build_scan_targets "$SUBNETS"
SCAN_TARGETS=("${SCAN_TARGETS[@]}")
(( ${#SCAN_TARGETS[@]} > 0 )) || { log ERROR "No valid targets from --subnets"; exit 1; }

mkdir -p "$OUTPUT_DIR"
SCAN_REPORT_EXPORT_CSV="$EXPORT_CSV"
export SCAN_REPORT_EXPORT_CSV
EXTRA_META=$(jq -n \
  --arg target "$SUBNETS" \
  --argjson timeout_ms "$TIMEOUT_MS" \
  --argjson threads "$THREADS" \
  --argjson cve_only "$CVE_ONLY" \
  --argjson eot_hot_only "$EOT_HOT_ONLY" \
  --arg config_overlay "${CONFIG_OVERLAY:-}" \
  '{target:$target, timeout_ms:$timeout_ms, threads:$threads, cve_only:$cve_only, eot_hot_only:$eot_hot_only, config_overlay:$config_overlay}')
export_scan_report_init "$OUTPUT_DIR" "$REPORT_PREFIX" "$SECTOR" "$SCANNER_NAME" "$EXTRA_META"

log INFO "Scan starting | Sector: $SECTOR | Targets: ${#SCAN_TARGETS[@]} | Ports: ${#PORTS[@]} | Threads: $THREADS | Timeout: ${TIMEOUT_MS}ms"

if (( ! QUIET )); then
  SCAN_ENGINE_PROGRESS_HOOK=scan_engine_default_progress_hook
  export SCAN_ENGINE_PROGRESS_HOOK
fi
scan_engine_reset_progress

run_tcp_port_scan "$THREADS" "$TIMEOUT_MS"

export_scan_report_set_scan_stats "${#SCAN_TARGETS[@]}" "${#PORTS[@]}" "$(( (SECONDS - SCAN_REPORT_START_EPOCH) * 1000 ))"
JSON_PATH="$(export_scan_report_finalize)"
if [[ "$EXPORT_CSV" == "1" && -f "$SCAN_REPORT_CSV_PATH" ]]; then
  log INFO "Scan complete | Findings: $SCAN_ENGINE_FINDINGS | JSON: $JSON_PATH | CSV: $SCAN_REPORT_CSV_PATH"
else
  log INFO "Scan complete | Findings: $SCAN_ENGINE_FINDINGS | Report: $JSON_PATH"
fi
