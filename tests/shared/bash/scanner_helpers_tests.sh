#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../../../scanners/_shared/scanner_helpers.sh
source "${ROOT}/scanners/_shared/scanner_helpers.sh"

hosts=$(expand_cidr '192.168.1.0/24' | wc -l)
[[ "$hosts" -eq 254 ]] || { echo "expand_cidr /24 expected 254 hosts, got $hosts" >&2; exit 1; }

mapfile -t range_hosts < <(expand_cidr '10.0.0.0/24')
first="${range_hosts[0]}"
last="${range_hosts[${#range_hosts[@]}-1]}"
[[ "$first" == "10.0.0.1" ]] || { echo "expand_cidr first host expected 10.0.0.1, got $first" >&2; exit 1; }
[[ "$last" == "10.0.0.254" ]] || { echo "expand_cidr last host expected 10.0.0.254, got $last" >&2; exit 1; }

validate_cidr '192.168.10.0/24' || { echo "validate_cidr rejected valid /24" >&2; exit 1; }
validate_cidr 'not-a-cidr' && { echo "validate_cidr accepted invalid CIDR" >&2; exit 1; }

build_scan_targets '192.168.10.0/24,192.168.10.0/24'
[[ "${#SCAN_TARGETS[@]}" -eq 254 ]] || { echo "build_scan_targets dedup expected 254, got ${#SCAN_TARGETS[@]}" >&2; exit 1; }

build_scan_targets '10.0.1.0/24,10.0.2.0/24'
[[ "${#SCAN_TARGETS[@]}" -eq 508 ]] || { echo "build_scan_targets multi-CIDR expected 508, got ${#SCAN_TARGETS[@]}" >&2; exit 1; }

printf 'Shared scanner helper tests passed.\n'
