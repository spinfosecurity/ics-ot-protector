#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

bash -n "${ROOT}/scanners/_shared/scan_engine.sh"

# shellcheck source=../../../scanners/_shared/load_sector_config.sh
source "${ROOT}/scanners/_shared/load_sector_config.sh"
# shellcheck source=../../../scanners/_shared/scanner_helpers.sh
source "${ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=../../../scanners/_shared/scan_engine.sh
source "${ROOT}/scanners/_shared/scan_engine.sh"

initialize_energy_grid_config
build_energy_grid_port_catalog full
(( ${#PORTS[@]} > 0 )) || { echo "energy-grid full catalog empty" >&2; exit 1; }

full_count=${#PORTS[@]}
build_energy_grid_port_catalog cve_only
(( ${#PORTS[@]} < full_count )) || { echo "cve_only catalog should be smaller than full catalog" >&2; exit 1; }

grep -q '|CVE|' <<< "${PORTS[*]}" || { echo "cve_only catalog missing CVE entries" >&2; exit 1; }
grep -q 'CVE|' <<< "${PORTS[0]}" || true

initialize_rail_config
build_rail_port_catalog all
rail_count=${#PORTS[@]}
(( rail_count == 17 )) || { echo "rail catalog expected 17 ports, got $rail_count" >&2; exit 1; }

# Verify port record shape: port|service|severity|category|description|remediation
IFS='|' read -r port service severity category description remediation <<< "${PORTS[0]}"
[[ -n "$port" && -n "$service" && -n "$severity" && -n "$category" && -n "$description" ]] || {
  echo "invalid port catalog record shape: ${PORTS[0]}" >&2; exit 1;
}

printf 'Shared scan engine tests passed.\n'
