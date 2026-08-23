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
# shellcheck source=../_shared/scanner_helpers.sh
source "${REPO_ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=../_shared/export_scan_report.sh
source "${REPO_ROOT}/scanners/_shared/export_scan_report.sh"
# shellcheck source=../_shared/scan_engine.sh
source "${REPO_ROOT}/scanners/_shared/scan_engine.sh"
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
# Helpers
# ---------------------------------------------------------------------------
log() {
  local level="$1"; shift
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

build_port_catalog() {
  if [[ "$EOT_HOT_ONLY" -eq 1 ]]; then
    build_rail_port_catalog eothot
  else
    build_rail_port_catalog all
  fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
run_rop_scan() {
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

  [[ -n "$SUBNETS" ]] || { printf '[ERROR] --subnets is required\n' >&2; exit 1; }

  [[ "$TIMEOUT_MS" =~ ^[0-9]+$ ]] && (( TIMEOUT_MS >= 100 && TIMEOUT_MS <= 10000 )) || {
    printf '[ERROR] --timeout-ms must be an integer between 100 and 10000\n' >&2; exit 1;
  }

  [[ "$THREADS" =~ ^[0-9]+$ ]] && (( THREADS >= 1 && THREADS <= 512 )) || {
    printf '[ERROR] --threads must be an integer between 1 and 512\n' >&2; exit 1;
  }

  mkdir -p "$OUTPUT_DIR"
  export_scan_report_init "$OUTPUT_DIR" "ROP-results" "rail" "Rail-OT-Protector"

  build_scan_targets "$SUBNETS"
  SCAN_TARGETS=("${SCAN_TARGETS[@]}")
  (( ${#SCAN_TARGETS[@]} > 0 )) || { log ERROR 'No valid targets generated — check --subnets input'; exit 1; }

  build_port_catalog

  log INFO "Scan starting | Targets: ${#SCAN_TARGETS[@]} | Ports: ${#PORTS[@]} | Threads: $THREADS | Timeout: ${TIMEOUT_MS}ms | EotHotOnly: $EOT_HOT_ONLY"

  run_tcp_port_scan "$THREADS" "$TIMEOUT_MS"

  JSON_PATH="$(export_scan_report_finalize)"
  log INFO "Scan complete | Report: $JSON_PATH"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  run_rop_scan "$@"
fi
