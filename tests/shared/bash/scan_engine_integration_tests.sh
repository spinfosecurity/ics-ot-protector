#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

command -v python3 >/dev/null 2>&1 || { echo "python3 required for integration tests" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required for integration tests" >&2; exit 1; }

# shellcheck source=../../../scanners/_shared/scanner_helpers.sh
source "${ROOT}/scanners/_shared/scanner_helpers.sh"
# shellcheck source=../../../scanners/_shared/export_scan_report.sh
source "${ROOT}/scanners/_shared/export_scan_report.sh"
# shellcheck source=../../../scanners/_shared/scan_engine.sh
source "${ROOT}/scanners/_shared/scan_engine.sh"

LISTEN_PORT=$(( 45000 + RANDOM % 1000 ))
MOCK_PID=""

start_mock_listener() {
  python3 - "$LISTEN_PORT" <<'PY' &
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port))
s.listen(5)
time.sleep(25)
PY
  MOCK_PID=$!
  for _ in $(seq 1 20); do
    if test_tcp_port 127.0.0.1 "$LISTEN_PORT" 1; then
      return 0
    fi
    sleep 0.1
  done
  echo "mock listener failed to start on port $LISTEN_PORT" >&2
  return 1
}

cleanup() {
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null || true
  wait "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

start_mock_listener

TMP_DIR="$(mktemp -d)"
export_scan_report_init "$TMP_DIR" "integration-test" "water" "test-scanner"
SCAN_REPORT_EXPORT_CSV=1
export SCAN_REPORT_EXPORT_CSV

PORTS=("${LISTEN_PORT}|Mock Service|HIGH|Test|Integration test port|Verify segmentation")
SCAN_TARGETS=("127.0.0.1")
SCAN_ENGINE_FINDINGS=0
run_tcp_port_scan 1 500

(( SCAN_ENGINE_FINDINGS >= 1 )) || { echo "expected at least one finding, got $SCAN_ENGINE_FINDINGS" >&2; exit 1; }

export_scan_report_set_scan_stats 1 1 100
JSON_PATH="$(export_scan_report_finalize)"

[[ -f "$JSON_PATH" ]] || { echo "missing json report" >&2; exit 1; }
[[ -f "${JSON_PATH%.json}.csv" ]] || { echo "missing csv report" >&2; exit 1; }
grep -q '"summary"' "$JSON_PATH" || { echo "missing summary in json metadata" >&2; exit 1; }
grep -q '127.0.0.1' "${JSON_PATH%.json}.csv" || { echo "csv missing host" >&2; exit 1; }

rm -rf "$TMP_DIR"
trap - EXIT
cleanup

printf 'Scan engine integration tests passed.\n'
