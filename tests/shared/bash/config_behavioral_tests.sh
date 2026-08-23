#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../../../scanners/_shared/load_sector_config.sh
source "${ROOT}/scanners/_shared/load_sector_config.sh"

PASS=0; FAIL=0
pass() { (( PASS++ )) || true; printf "  ✓ %s\n" "$1"; }
fail() { (( FAIL++ )) || true; printf "  ✗ %s\n" "$1"; }

echo "=== energy-grid config ==="
initialize_energy_grid_config
[[ ${#cve_checks[@]} -eq 4 ]] && pass "4 CVE checks loaded" || fail "expected 4 CVE checks got ${#cve_checks[@]}"
[[ -n "${cve_checks[CVE-2026-42945]:-}" ]] && pass "CVE-2026-42945 present" || fail "CVE-2026-42945 missing"
[[ -n "${remote_access_ports[23]:-}" ]] && pass "Telnet port 23 in remote access" || fail "port 23 missing"
[[ -n "${ics_ports[20000]:-}" ]] && pass "DNP3 port 20000 in ICS table" || fail "port 20000 missing"
build_energy_grid_port_catalog full
[[ ${#PORTS[@]} -gt 10 ]] && pass "energy-grid port catalog built (${#PORTS[@]} entries)" || fail "energy-grid port catalog too small"
build_energy_grid_port_catalog cve_only
cve_only_count=${#PORTS[@]}
build_energy_grid_port_catalog full
[[ ${#PORTS[@]} -gt $cve_only_count ]] && pass "full catalog larger than cve_only" || fail "cve_only filter not working"

echo ""
echo "=== water config ==="
initialize_water_config
[[ ${#REMOTE_ACCESS_PORTS[@]} -eq 8 ]] && pass "8 remote access ports" || fail "expected 8 remote access ports got ${#REMOTE_ACCESS_PORTS[@]}"
build_water_port_catalog
[[ ${#PORTS[@]} -gt 10 ]] && pass "water port catalog built (${#PORTS[@]} entries)" || fail "water port catalog too small"

echo ""
echo "=== bas config ==="
initialize_bas_config
[[ ${#CRITICAL_BAS_PORTS[@]} -eq 9 ]] && pass "9 BAS protocol ports" || fail "expected 9 BAS ports"
build_bas_port_catalog
[[ ${#PORTS[@]} -gt 10 ]] && pass "bas port catalog built (${#PORTS[@]} entries)" || fail "bas port catalog too small"
[[ -n "${VENDOR_ALERT_PORTS[5489]:-}" ]] && pass "Honeywell vendor alert on 5489" || fail "5489 missing"
[[ -n "${THREAT_CONTEXT[BACnet/IP]:-}" ]] && pass "BACnet/IP threat context" || fail "BACnet/IP context missing"

echo ""
echo "=== rail config ==="
initialize_rail_config
build_rail_port_catalog all
[[ ${#PORTS[@]} -eq 17 ]] && pass "17 rail ports in full catalog" || fail "expected 17 ports got ${#PORTS[@]}"
build_rail_port_catalog eothot
[[ ${#PORTS[@]} -eq 2 ]] && pass "2 ports in EotHot-only catalog" || fail "expected 2 EotHot ports got ${#PORTS[@]}"

echo ""
printf "Sector config tests: %d passed, %d failed\n" "$PASS" "$FAIL"
(( FAIL == 0 ))
