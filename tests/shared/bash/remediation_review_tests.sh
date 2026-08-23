#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# shellcheck source=../../../scanners/_shared/remediation_metadata.sh
source "${ROOT}/scanners/_shared/remediation_metadata.sh"

remediation_metadata_for_finding "CRITICAL" "Remote Access"
[[ "$REMEDIATION_PRIORITY" == "IMMEDIATE" && "$REMEDIATION_ACTION" == "block" && "$OWNER_ROLE" == "security" ]] || {
  echo "CRITICAL remote access metadata wrong: $REMEDIATION_PRIORITY $REMEDIATION_ACTION $OWNER_ROLE" >&2; exit 1;
}

remediation_metadata_for_finding "HIGH" "OT Protocol Exposure"
[[ "$REMEDIATION_PRIORITY" == "URGENT" && "$REMEDIATION_ACTION" == "segment" && "$OWNER_ROLE" == "ot" ]] || {
  echo "HIGH OT metadata wrong" >&2; exit 1;
}

input='[{"Timestamp":"t","Host":"10.0.0.1","Port":502,"Service":"Modbus","Severity":"HIGH","Category":"OT Protocol Exposure","Description":"d","Remediation":"r"}]'
enriched="$(export_scan_report_enrich_findings_json "$input")"
echo "$enriched" | grep -q '"RemediationPriority":"URGENT"' || { echo "enrich failed" >&2; exit 1; }

summary="$(export_scan_report_build_extended_summary_json "$enriched" 10 5 1000)"
echo "$summary" | grep -q 'findings_by_category' || { echo "summary missing category breakdown" >&2; exit 1; }
echo "$summary" | grep -q 'top_hosts' || { echo "summary missing top_hosts" >&2; exit 1; }

chmod +x "${ROOT}/scripts/review_scan_report.sh"
out="$(bash "${ROOT}/scripts/review_scan_report.sh" "${ROOT}/docs/sample-report.json")"
echo "$out" | grep -q 'IMMEDIATE' || { echo "review script missing IMMEDIATE" >&2; exit 1; }

printf 'Remediation and review tests passed.\n'
