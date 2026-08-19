#!/usr/bin/env bash
# Unified JSON/CSV export helpers for ICS OT Protector sector scanners.
# Source this file; do not execute directly.

export_scan_report_init() {
  local output_dir="$1"
  local prefix="$2"

  mkdir -p "$output_dir"

  local timestamp
  timestamp="$(date +%Y%m%d-%H%M%S)"
  SCAN_REPORT_OUTPUT_DIR="$output_dir"
  SCAN_REPORT_PREFIX="$prefix"
  SCAN_REPORT_TIMESTAMP="$timestamp"
  SCAN_REPORT_JSON_TMP="$(mktemp)"
  SCAN_REPORT_CSV_PATH="${output_dir}/${prefix}-${timestamp}.csv"
  SCAN_REPORT_JSON_PATH="${output_dir}/${prefix}-${timestamp}.json"

  echo '[]' > "$SCAN_REPORT_JSON_TMP"
  printf 'Timestamp,Host,Port,Service,Severity,Category,Description,Remediation\n' > "$SCAN_REPORT_CSV_PATH"
  export SCAN_REPORT_OUTPUT_DIR SCAN_REPORT_PREFIX SCAN_REPORT_TIMESTAMP
  export SCAN_REPORT_JSON_TMP SCAN_REPORT_CSV_PATH SCAN_REPORT_JSON_PATH
}

export_scan_report_append() {
  local host="$1"
  local port="$2"
  local service="$3"
  local severity="$4"
  local category="$5"
  local description="$6"
  local remediation="${7:-}"
  local ts
  ts="$(date '+%Y-%m-%dT%H:%M:%S')"

  local escaped_service escaped_description escaped_remediation
  escaped_service=$(printf '%s' "$service" | sed 's/"/""/g')
  escaped_description=$(printf '%s' "$description" | sed 's/"/""/g')
  escaped_remediation=$(printf '%s' "$remediation" | sed 's/"/""/g')

  printf '%s,%s,%s,"%s",%s,%s,"%s","%s"\n' \
    "$ts" "$host" "$port" "$escaped_service" "$severity" "$category" \
    "$escaped_description" "$escaped_remediation" >> "$SCAN_REPORT_CSV_PATH"

  if command -v jq >/dev/null 2>&1; then
    jq --arg ts "$ts" --arg h "$host" --argjson p "$port" \
       --arg svc "$service" --arg sev "$severity" --arg cat "$category" \
       --arg desc "$description" --arg rem "$remediation" \
       '. += [{Timestamp:$ts,Host:$h,Port:$p,Service:$svc,Severity:$sev,Category:$cat,Description:$desc,Remediation:$rem}]' \
       "$SCAN_REPORT_JSON_TMP" > "${SCAN_REPORT_JSON_TMP}.next" && mv "${SCAN_REPORT_JSON_TMP}.next" "$SCAN_REPORT_JSON_TMP"
  fi
}

export_scan_report_finalize() {
  if [[ -n "${SCAN_REPORT_JSON_TMP:-}" && -f "$SCAN_REPORT_JSON_TMP" ]]; then
    mv "$SCAN_REPORT_JSON_TMP" "$SCAN_REPORT_JSON_PATH"
  fi
  printf '%s|%s\n' "$SCAN_REPORT_JSON_PATH" "$SCAN_REPORT_CSV_PATH"
}
