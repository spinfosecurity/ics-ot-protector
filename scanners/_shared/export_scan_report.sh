#!/usr/bin/env bash
# Unified JSON export helpers for ICS OT Protector sector scanners.
# Source this file; do not execute directly.

export_scan_report_init() {
  local output_dir="$1"
  local prefix="$2"
  local sector="${3:-unknown}"
  local scanner="${4:-unknown}"

  mkdir -p "$output_dir"

  local timestamp
  timestamp="$(date +%Y%m%d-%H%M%S)"
  SCAN_REPORT_OUTPUT_DIR="$output_dir"
  SCAN_REPORT_PREFIX="$prefix"
  SCAN_REPORT_TIMESTAMP="$timestamp"
  SCAN_REPORT_SECTOR="$sector"
  SCAN_REPORT_SCANNER="$scanner"
  SCAN_REPORT_JSON_TMP="$(mktemp)"
  SCAN_REPORT_JSON_PATH="${output_dir}/${prefix}-${timestamp}.json"
  SCAN_REPORT_LOCK_DIR="$(mktemp -d)"
  SCAN_REPORT_EXTRA_META="${5:-}"

  echo '[]' > "$SCAN_REPORT_JSON_TMP"
  export SCAN_REPORT_OUTPUT_DIR SCAN_REPORT_PREFIX SCAN_REPORT_TIMESTAMP
  export SCAN_REPORT_SECTOR SCAN_REPORT_SCANNER SCAN_REPORT_JSON_TMP
  export SCAN_REPORT_JSON_PATH SCAN_REPORT_LOCK_DIR SCAN_REPORT_EXTRA_META
}

export_scan_report_set_metadata() {
  local key="$1"
  local value="$2"
  eval "SCAN_REPORT_META_${key}=\"\$value\""
  export "SCAN_REPORT_META_${key}"
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

  if ! command -v jq >/dev/null 2>&1; then
    echo "export_scan_report_append requires jq" >&2
    return 1
  fi

  while ! mkdir "$SCAN_REPORT_LOCK_DIR/write.lock" 2>/dev/null; do sleep 0.005; done
  jq --arg ts "$ts" --arg h "$host" --argjson p "$port" \
     --arg svc "$service" --arg sev "$severity" --arg cat "$category" \
     --arg desc "$description" --arg rem "$remediation" \
     '. += [{Timestamp:$ts,Host:$h,Port:$p,Service:$svc,Severity:$sev,Category:$cat,Description:$desc,Remediation:$rem}]' \
     "$SCAN_REPORT_JSON_TMP" > "${SCAN_REPORT_JSON_TMP}.next" && mv "${SCAN_REPORT_JSON_TMP}.next" "$SCAN_REPORT_JSON_TMP"
  rmdir "$SCAN_REPORT_LOCK_DIR/write.lock"
}

export_scan_report_finalize() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "export_scan_report_finalize requires jq" >&2
    return 1
  fi

  local metadata='{}'
  if [[ -n "${SCAN_REPORT_SECTOR:-}" || -n "${SCAN_REPORT_SCANNER:-}" ]]; then
    metadata=$(jq -n \
      --arg sector "${SCAN_REPORT_SECTOR:-unknown}" \
      --arg scanner "${SCAN_REPORT_SCANNER:-unknown}" \
      '{sector:$sector, scanner:$scanner}')
  fi
  if [[ -n "${SCAN_REPORT_EXTRA_META:-}" && "${SCAN_REPORT_EXTRA_META}" != "{}" ]]; then
    metadata=$(jq -n --argjson base "$metadata" --argjson extra "$SCAN_REPORT_EXTRA_META" '$base + $extra')
  fi

  local generated_at
  generated_at="$(date '+%Y-%m-%dT%H:%M:%S')"
  jq -n \
    --arg schema_version "1.0" \
    --arg generated_at "$generated_at" \
    --argjson metadata "$metadata" \
    --slurpfile findings "$SCAN_REPORT_JSON_TMP" \
    '{schema_version:$schema_version, generated_at:$generated_at, metadata:$metadata, findings:$findings[0]}' \
    > "$SCAN_REPORT_JSON_PATH"

  rm -rf "$SCAN_REPORT_LOCK_DIR"
  rm -f "$SCAN_REPORT_JSON_TMP"
  printf '%s\n' "$SCAN_REPORT_JSON_PATH"
}

export_scan_report_write() {
  # One-shot export for scanners that collect findings in memory.
  local output_dir="$1"
  local prefix="$2"
  local sector="$3"
  local scanner="$4"
  local findings_json="$5"

  mkdir -p "$output_dir"
  local timestamp generated_at report_path
  timestamp="$(date +%Y%m%d-%H%M%S)"
  generated_at="$(date '+%Y-%m-%dT%H:%M:%S')"
  report_path="${output_dir}/${prefix}-${timestamp}.json"

  jq -n \
    --arg schema_version "1.0" \
    --arg generated_at "$generated_at" \
    --arg sector "$sector" \
    --arg scanner "$scanner" \
    --argjson findings "$findings_json" \
    '{schema_version:$schema_version, generated_at:$generated_at, metadata:{sector:$sector, scanner:$scanner}, findings:$findings}' \
    > "$report_path"

  printf '%s\n' "$report_path"
}
