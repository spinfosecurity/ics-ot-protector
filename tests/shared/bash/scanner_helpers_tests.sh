#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../../../scanners/_shared/scanner_helpers.sh
source "${ROOT}/scanners/_shared/scanner_helpers.sh"

[[ "$(get_network_prefix '192.168.10.0/24')" == "192.168.10" ]] || { echo "get_network_prefix failed for /24" >&2; exit 1; }
[[ "$(get_network_prefix '10.0.1.0/24')" == "10.0.1" ]] || { echo "get_network_prefix failed for 10.0.1" >&2; exit 1; }

hosts=$(get_subnet_hosts '192.168.1.0/24' | wc -l)
[[ "$hosts" -eq 254 ]] || { echo "get_subnet_hosts expected 254 hosts, got $hosts" >&2; exit 1; }

printf 'Shared scanner helper tests passed.\n'
