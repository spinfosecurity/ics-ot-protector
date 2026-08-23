#!/usr/bin/env bash
# Unified JSON/CSV export helpers for ICS OT Protector sector scanners.
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
  SCAN_REPORT_CSV_PATH="${output_dir}/${prefix}-${timestamp}.csv"
  SCAN_REPORT_LOCK_DIR="$(mktemp -d)"
  SCAN_REPORT_EXTRA_META="${5:-}"
  SCAN_REPORT_EXPORT_CSV="${SCAN_REPORT_EXPORT_CSV:-0}"
  SCAN_REPORT_START_EPOCH="${SECONDS:-0}"
  SCAN_REPORT_HOSTS_SCANNED=0
  SCAN_REPORT_PORTS_CHECKED=0
  SCAN_REPORT_DURATION_MS=0

  echo '[]' > "$SCAN_REPORT_JSON_TMP"
  export SCAN_REPORT_OUTPUT_DIR SCAN_REPORT_PREFIX SCAN_REPORT_TIMESTAMP
  export SCAN_REPORT_SECTOR SCAN_REPORT_SCANNER SCAN_REPORT_JSON_TMP
  export SCAN_REPORT_JSON_PATH SCAN_REPORT_CSV_PATH SCAN_REPORT_LOCK_DIR
  export SCAN_REPORT_EXTRA_META SCAN_REPORT_EXPORT_CSV
  export SCAN_REPORT_START_EPOCH SCAN_REPORT_HOSTS_SCANNED SCAN_REPORT_PORTS_CHECKED
  export SCAN_REPORT_DURATION_MS
}

export_scan_report_set_scan_stats() {
  SCAN_REPORT_HOSTS_SCANNED="${1:-0}"
  SCAN_REPORT_PORTS_CHECKED="${2:-0}"
  SCAN_REPORT_DURATION_MS="${3:-0}"
  export SCAN_REPORT_HOSTS_SCANNED SCAN_REPORT_PORTS_CHECKED SCAN_REPORT_DURATION_MS
}

export_scan_report_build_summary_json() {
  local findings_file="$1"
  local hosts="${SCAN_REPORT_HOSTS_SCANNED:-0}"
  local ports="${SCAN_REPORT_PORTS_CHECKED:-0}"
  local duration_ms="${SCAN_REPORT_DURATION_MS:-0}"
  jq -n \
    --argjson hosts "$hosts" \
    --argjson ports "$ports" \
    --argjson duration_ms "$duration_ms" \
    --slurpfile findings "$findings_file" \
    '
    ($findings[0]) as $f |
    {
      hosts_scanned: $hosts,
      ports_checked: $ports,
      probes_total: ($hosts * $ports),
      findings_total: ($f | length),
      findings_by_severity: (
        reduce $f[] as $item ({}; .[$item.Severity] = ((.[$item.Severity] // 0) + 1))
      ),
      duration_ms: $duration_ms
    }'
}

export_scan_report_write_csv() {
  local json_path="$1"
  local csv_path="$2"
  jq -r '
    ["Timestamp","Host","Port","Service","Severity","Category","Description","Remediation"],
    (.findings[]? | [.Timestamp, .Host, (.Port|tostring), .Service, .Severity, .Category, .Description, .Remediation])
    | @csv
  ' "$json_path" > "$csv_path"
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

  if (( SCAN_REPORT_DURATION_MS == 0 )); then
    SCAN_REPORT_DURATION_MS=$(( (SECONDS - SCAN_REPORT_START_EPOCH) * 1000 ))
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

  local summary
  summary=$(export_scan_report_build_summary_json "$SCAN_REPORT_JSON_TMP")
  metadata=$(jq -n --argjson base "$metadata" --argjson summary "$summary" '$base + {summary:$summary}')

  local generated_at
  generated_at="$(date '+%Y-%m-%dT%H:%M:%S')"
  jq -n \
    --arg schema_version "1.0" \
    --arg generated_at "$generated_at" \
    --argjson metadata "$metadata" \
    --slurpfile findings "$SCAN_REPORT_JSON_TMP" \
    '{schema_version:$schema_version, generated_at:$generated_at, metadata:$metadata, findings:$findings[0]}' \
    > "$SCAN_REPORT_JSON_PATH"

  if [[ "${SCAN_REPORT_EXPORT_CSV:-0}" == "1" ]]; then
    export_scan_report_write_csv "$SCAN_REPORT_JSON_PATH" "$SCAN_REPORT_CSV_PATH"
  fi

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
  local hosts_scanned="${6:-0}"
  local ports_checked="${7:-0}"
  local duration_ms="${8:-0}"
  local export_csv="${9:-0}"

  mkdir -p "$output_dir"
  local timestamp generated_at report_path csv_path summary metadata
  timestamp="$(date +%Y%m%d-%H%M%S)"
  generated_at="$(date '+%Y-%m-%dT%H:%M:%S')"
  report_path="${output_dir}/${prefix}-${timestamp}.json"
  csv_path="${output_dir}/${prefix}-${timestamp}.csv"

  summary=$(jq -n \
    --argjson hosts "$hosts_scanned" \
    --argjson ports "$ports_checked" \
    --argjson duration_ms "$duration_ms" \
    --argjson findings "$findings_json" \
    '{
      hosts_scanned: $hosts,
      ports_checked: $ports,
      probes_total: ($hosts * $ports),
      findings_total: ($findings | length),
      findings_by_severity: (reduce $findings[] as $item ({}; .[$item.Severity] = ((.[$item.Severity] // 0) + 1))),
      duration_ms: $duration_ms
    }')

  metadata=$(jq -n \
    --arg sector "$sector" \
    --arg scanner "$scanner" \
    --argjson summary "$summary" \
    '{sector:$sector, scanner:$scanner, summary:$summary}')

  jq -n \
    --arg schema_version "1.0" \
    --arg generated_at "$generated_at" \
    --argjson metadata "$metadata" \
    --argjson findings "$findings_json" \
    '{schema_version:$schema_version, generated_at:$generated_at, metadata:$metadata, findings:$findings}' \
    > "$report_path"

  if [[ "$export_csv" == "1" ]]; then
    export_scan_report_write_csv "$report_path" "$csv_path"
  fi

  printf '%s\n' "$report_path"
}
