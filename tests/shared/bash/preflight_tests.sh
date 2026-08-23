#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../../../scanners/_shared/scanner_helpers.sh
source "${ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=../../../scanners/_shared/preflight.sh
source "${ROOT}/scanners/_shared/preflight.sh"

preflight_check_dependencies

if preflight_validate_scan_scope "192.168.10.0/24" 0; then
  [[ "$PREFLIGHT_HOST_COUNT" -eq 254 ]] || { echo "expected 254 hosts for /24, got $PREFLIGHT_HOST_COUNT" >&2; exit 1; }
else
  echo "valid /24 should pass preflight" >&2; exit 1
fi

if preflight_validate_scan_scope "10.0.0.0/16" 0; then
  echo "expected /16 to require --force" >&2; exit 1
fi

if ! preflight_validate_scan_scope "10.0.0.0/16" 1; then
  echo "expected /16 to pass with force" >&2; exit 1
fi

if preflight_validate_scan_scope "not-a-cidr" 0; then
  echo "expected invalid cidr to fail" >&2; exit 1
fi

printf 'Preflight tests passed.\n'
