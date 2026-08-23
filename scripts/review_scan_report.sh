#!/usr/bin/env bash
# Offline triage review for ICS OT Protector JSON scan reports.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: review_scan_report.sh <report.json> [--markdown]

Prints a human-readable triage summary from a schema 1.0 scan report.
Use after a scan to prioritize remediation without re-running the scanner.
EOF
}

[[ $# -ge 1 ]] || { usage >&2; exit 1; }
REPORT="$1"
FORMAT="${2:-}"
[[ -f "$REPORT" ]] || { echo "Report not found: $REPORT" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

if [[ "$FORMAT" == "--markdown" ]]; then
  jq -r '
    "# Scan report review\n",
    "**Sector:** \(.metadata.sector // "unknown") | **Scanner:** \(.metadata.scanner // "unknown")",
    "**Generated:** \(.generated_at)",
    "",
    "## Summary",
    "- Hosts scanned: \(.metadata.summary.hosts_scanned // 0)",
    "- Findings: \(.metadata.summary.findings_total // 0)",
    "- Duration: \((.metadata.summary.duration_ms // 0) / 1000)s",
    "",
    "### By priority",
    (.metadata.summary.findings_by_priority // {} | to_entries[] | "- \(.key): \(.value)"),
    "",
    "### Top hosts",
    (.metadata.summary.top_hosts // [] | .[] | "- \(.host): \(.findings) finding(s)"),
    "",
    "## Findings (by priority)",
    (.findings | sort_by([
      (if .RemediationPriority == "IMMEDIATE" then 0 elif .RemediationPriority == "URGENT" then 1 else 2 end),
      .Host,
      .Port
    ]))[] |
    "### [\(.RemediationPriority // "PLANNED")] \(.Host):\(.Port) — \(.Service)",
    "- **Severity:** \(.Severity) | **Category:** \(.Category) | **Owner:** \(.OwnerRole // "ot") | **Action:** \(.RemediationAction // "verify")",
    "- \(.Description)",
    "- _Remediation:_ \(.Remediation)",
    ""
  ' "$REPORT"
  exit 0
fi

echo "=== ICS OT Protector — Report Review ==="
jq -r '
  "Sector:     \(.metadata.sector // "unknown")",
  "Scanner:    \(.metadata.scanner // "unknown")",
  "Generated:  \(.generated_at)",
  "",
  "SUMMARY",
  "  Hosts scanned: \(.metadata.summary.hosts_scanned // 0)",
  "  Findings:      \(.metadata.summary.findings_total // 0)",
  "  Duration:      \((.metadata.summary.duration_ms // 0) / 1000)s",
  "",
  "BY PRIORITY"
' "$REPORT"

jq -r '.metadata.summary.findings_by_priority // {} | to_entries[] | "  \(.key): \(.value)"' "$REPORT"

echo ""
echo "TOP HOSTS"
jq -r '.metadata.summary.top_hosts // [] | .[] | "  \(.host): \(.findings) finding(s)"' "$REPORT"

echo ""
echo "FINDINGS"
jq -r '
  (.findings | sort_by([
    (if .RemediationPriority == "IMMEDIATE" then 0 elif .RemediationPriority == "URGENT" then 1 else 2 end),
    .Host,
    .Port
  ]))[] |
  "[\(.RemediationPriority // "PLANNED")] \(.Host):\(.Port) \(.Service) (\(.Severity))",
  "  owner=\(.OwnerRole // "ot") action=\(.RemediationAction // "verify") category=\(.Category)",
  "  \(.Description)",
  "  -> \(.Remediation)",
  ""
' "$REPORT"
