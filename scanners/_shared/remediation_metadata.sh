#!/usr/bin/env bash
# Derive structured remediation metadata from finding severity and category.
# Source this file; do not execute directly.

remediation_metadata_for_finding() {
  local severity="$1"
  local category="${2:-General}"
  local cat_lower sev_upper
  sev_upper=$(printf '%s' "$severity" | tr '[:lower:]' '[:upper:]')
  cat_lower=$(printf '%s' "$category" | tr '[:upper:]' '[:lower:]')

  REMEDIATION_PRIORITY="PLANNED"
  REMEDIATION_ACTION="verify"
  OWNER_ROLE="ot"

  case "$sev_upper" in
    CRITICAL)
      REMEDIATION_PRIORITY="IMMEDIATE"
      REMEDIATION_ACTION="block"
      if [[ "$cat_lower" == *remote* ]]; then
        OWNER_ROLE="security"
      else
        OWNER_ROLE="ot"
      fi
      ;;
    HIGH)
      REMEDIATION_PRIORITY="URGENT"
      if [[ "$cat_lower" == *cve* ]]; then
        REMEDIATION_ACTION="patch"
        OWNER_ROLE="ot"
      elif [[ "$cat_lower" == *remote* ]]; then
        REMEDIATION_ACTION="block"
        OWNER_ROLE="security"
      elif [[ "$cat_lower" == *ot* || "$cat_lower" == *ics* || "$cat_lower" == *bas* || "$cat_lower" == *protocol* || "$cat_lower" == *eothot* ]]; then
        REMEDIATION_ACTION="segment"
        OWNER_ROLE="ot"
      else
        REMEDIATION_ACTION="segment"
        OWNER_ROLE="ot"
      fi
      ;;
    MEDIUM)
      REMEDIATION_PRIORITY="PLANNED"
      REMEDIATION_ACTION="verify"
      OWNER_ROLE="it"
      ;;
    *)
      REMEDIATION_PRIORITY="PLANNED"
      REMEDIATION_ACTION="verify"
      OWNER_ROLE="ot"
      ;;
  esac
}

export_scan_report_enrich_findings_json() {
  local findings_json="$1"
  python3 - "$findings_json" <<'PY'
import json, sys

raw = sys.argv[1]
findings = json.loads(raw) if raw.strip() else []

def classify(severity: str, category: str) -> dict:
    sev = (severity or "").upper()
    cat = (category or "General").lower()
    priority, action, owner = "PLANNED", "verify", "ot"
    if sev == "CRITICAL":
        priority, action = "IMMEDIATE", "block"
        owner = "security" if "remote" in cat else "ot"
    elif sev == "HIGH":
        priority = "URGENT"
        if "cve" in cat:
            action, owner = "patch", "ot"
        elif "remote" in cat:
            action, owner = "block", "security"
        else:
            action, owner = "segment", "ot"
    elif sev == "MEDIUM":
        priority, action, owner = "PLANNED", "verify", "it"
    return {
        "RemediationPriority": priority,
        "RemediationAction": action,
        "OwnerRole": owner,
    }

for item in findings:
    item.update(classify(item.get("Severity", ""), item.get("Category", "")))

print(json.dumps(findings, separators=(",", ":")))
PY
}

export_scan_report_build_extended_summary_json() {
  local findings_json="$1"
  local hosts="${2:-0}"
  local ports="${3:-0}"
  local duration_ms="${4:-0}"

  python3 - "$findings_json" "$hosts" "$ports" "$duration_ms" <<'PY'
import json, sys
from collections import Counter

findings = json.loads(sys.argv[1]) if sys.argv[1].strip() else []
hosts = int(sys.argv[2])
ports = int(sys.argv[3])
duration_ms = int(sys.argv[4])

by_severity = Counter(f.get("Severity", "UNKNOWN") for f in findings)
by_category = Counter(f.get("Category", "General") for f in findings)
by_priority = Counter(f.get("RemediationPriority", "PLANNED") for f in findings)
by_owner = Counter(f.get("OwnerRole", "ot") for f in findings)
by_host = Counter(f.get("Host", "") for f in findings)
top_hosts = [{"host": h, "findings": c} for h, c in by_host.most_common(5) if h]

summary = {
    "hosts_scanned": hosts,
    "ports_checked": ports,
    "probes_total": hosts * ports,
    "findings_total": len(findings),
    "findings_by_severity": dict(by_severity),
    "findings_by_category": dict(by_category),
    "findings_by_priority": dict(by_priority),
    "findings_by_owner_role": dict(by_owner),
    "top_hosts": top_hosts,
    "duration_ms": duration_ms,
}
print(json.dumps(summary, separators=(",", ":")))
PY
}
