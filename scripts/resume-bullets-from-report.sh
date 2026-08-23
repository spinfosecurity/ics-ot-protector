#!/usr/bin/env bash
# Emit copy-paste resume bullets from a schema 1.0 scan report JSON file.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: resume-bullets-from-report.sh <report.json>

Prints resume-style bullet points derived from report metadata and findings.
EOF
}

[[ $# -ge 1 ]] || { usage >&2; exit 1; }
REPORT="$1"
[[ -f "$REPORT" ]] || { echo "Report not found: $REPORT" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

sector=$(jq -r '.metadata.sector // "OT"' "$REPORT")
scanner=$(jq -r '.metadata.scanner // "ICS scanner"' "$REPORT")
hosts=$(jq -r '.metadata.summary.hosts_scanned // 0' "$REPORT")
findings=$(jq -r '.metadata.summary.findings_total // 0' "$REPORT")
critical=$(jq -r '.metadata.summary.findings_by_severity.CRITICAL // 0' "$REPORT")
high=$(jq -r '.metadata.summary.findings_by_severity.HIGH // 0' "$REPORT")
immediate=$(jq -r '.metadata.summary.findings_by_priority.IMMEDIATE // 0' "$REPORT")
categories=$(jq -r '(.metadata.summary.findings_by_category // {}) | keys | join(", ")' "$REPORT")
top_host=$(jq -r '.metadata.summary.top_hosts[0].host // "n/a"' "$REPORT")

cat <<EOF
Suggested resume bullets (edit for accuracy and voice):

- Delivered ${scanner} assessment output for a ${sector} sector scope: ${hosts} hosts reviewed, ${findings} exposure finding(s) (${critical} critical, ${high} high) with structured JSON reporting for IT/OT triage.
- Prioritized remediation using severity and priority metadata (${immediate} immediate item(s)); categories included ${categories:-general OT exposure}.
- Produced operator-readable triage artifacts (JSON summary, offline review CLI) suitable for handoff to OT owners—top host by finding count: ${top_host}.
- Followed authorized defensive assessment practice: TCP reachability checks only, CISA-aligned remediation notes, no credential testing or exploit payloads.
EOF
