#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

command -v jq >/dev/null 2>&1 || { echo "jq is required for export tests" >&2; exit 1; }

# shellcheck source=../../../scanners/_shared/export_scan_report.sh
source "${ROOT}/scanners/_shared/export_scan_report.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export_scan_report_init "$TMP_DIR" "launcher-test" "water" "WUP WUP"
export_scan_report_append "10.0.0.5" 502 "ICS-PROTOCOL:Modbus" "HIGH" "ICS" "Modbus exposed" "Segment network"
JSON_PATH="$(export_scan_report_finalize)"

[[ -f "$JSON_PATH" ]] || { echo "Missing JSON export: $JSON_PATH" >&2; exit 1; }
grep -q '10.0.0.5' "$JSON_PATH"
grep -q '"schema_version"' "$JSON_PATH"

PS1_LAUNCHER="${ROOT}/scripts/ics-ot-protector.ps1"
SH_LAUNCHER="${ROOT}/scripts/ics-ot-protector.sh"
[[ -f "$PS1_LAUNCHER" ]] || { echo "Missing PowerShell launcher" >&2; exit 1; }
[[ -f "$SH_LAUNCHER" ]] || { echo "Missing Bash launcher" >&2; exit 1; }
bash -n "$SH_LAUNCHER"
bash -n "${ROOT}/scanners/_shared/run_sector_scan.sh"

"$SH_LAUNCHER" --help | grep -qi 'energy-grid'
"$SH_LAUNCHER" --help | grep -qi 'scan --sector'

if "$SH_LAUNCHER" invalid-sector 2>/dev/null; then
  echo "Expected unknown sector to fail" >&2
  exit 1
fi

printf 'Launcher and export tests passed.\n'
