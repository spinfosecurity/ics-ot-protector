#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# shellcheck source=../../../scanners/_shared/export_scan_report.sh
source "${ROOT}/scanners/_shared/export_scan_report.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export_scan_report_init "$TMP_DIR" "launcher-test"
export_scan_report_append "10.0.0.5" 502 "ICS-PROTOCOL:Modbus" "HIGH" "ICS" "Modbus exposed" "Segment network"
IFS='|' read -r JSON_PATH CSV_PATH < <(export_scan_report_finalize)

[[ -f "$JSON_PATH" ]] || { echo "Missing JSON export: $JSON_PATH" >&2; exit 1; }
[[ -f "$CSV_PATH" ]] || { echo "Missing CSV export: $CSV_PATH" >&2; exit 1; }
grep -q '10.0.0.5' "$CSV_PATH"

PS1_LAUNCHER="${ROOT}/scripts/ics-ot-protector.ps1"
SH_LAUNCHER="${ROOT}/scripts/ics-ot-protector.sh"
[[ -f "$PS1_LAUNCHER" ]] || { echo "Missing PowerShell launcher" >&2; exit 1; }
[[ -f "$SH_LAUNCHER" ]] || { echo "Missing Bash launcher" >&2; exit 1; }
bash -n "$SH_LAUNCHER"

# Help text smoke test
"$SH_LAUNCHER" --help | grep -qi 'energy-grid'

# Unknown sector exits non-zero
if "$SH_LAUNCHER" invalid-sector 2>/dev/null; then
  echo "Expected unknown sector to fail" >&2
  exit 1
fi

printf 'Launcher and export tests passed.\n'
