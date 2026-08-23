#!/usr/bin/env bash
# Shared TCP port scan engine for ICS OT Protector Bash scanners.
# Source this file; do not execute directly.
#
# Port catalog record format (pipe-delimited):
#   port|service|severity|category|description|remediation
#
# Before calling run_tcp_port_scan, set:
#   SCAN_TARGETS[]  — host IP addresses
#   PORTS[]         — port catalog records
#
# Optional hooks (function names):
#   SCAN_ENGINE_FINDING_HOOK   — (host, port, service, severity, category, description, remediation)
#   SCAN_ENGINE_PROGRESS_HOOK  — (host, processed, total) — sequential mode only

scan_engine_timeout_sec() {
  awk "BEGIN{printf \"%.3f\",${1}/1000}"
}

scan_engine_default_finding_hook() {
  local host="$1" port="$2" service="$3" severity="$4" category="$5" description="$6" remediation="$7"
  export_scan_report_append "$host" "$port" "$service" "$severity" "$category" "$description" "$remediation"
  printf '[%s] [%s] %s:%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$severity" "$host" "$port" "$description"
}

scan_engine_emit_finding() {
  local hook="${SCAN_ENGINE_FINDING_HOOK:-scan_engine_default_finding_hook}"
  "$hook" "$@"
  SCAN_ENGINE_FINDINGS=$((SCAN_ENGINE_FINDINGS + 1))
}

scan_engine_probe_host() {
  local host="$1" timeout_ms="$2" use_dedup="$3"
  local timeout_sec record port service severity category description remediation dedup_key
  timeout_sec=$(scan_engine_timeout_sec "$timeout_ms")

  local IFS=$'\n'
  for record in $PORT_CATALOG_STR; do
    [[ -z "$record" ]] && continue
    IFS='|' read -r port service severity category description remediation <<< "$record"
    if [[ "$use_dedup" == "1" ]]; then
      dedup_key="${host}:${port}"
      if [[ -n "${SCAN_ENGINE_DEDUP[$dedup_key]+x}" ]]; then
        continue
      fi
    fi
    if test_tcp_port "$host" "$port" "$timeout_sec"; then
      if [[ "$use_dedup" == "1" ]]; then
        SCAN_ENGINE_DEDUP[$dedup_key]=1
      fi
      scan_engine_emit_finding "$host" "$port" "$service" "$severity" "$category" "$description" "$remediation"
    fi
  done
}

scan_engine_parallel_worker() {
  scan_engine_probe_host "$1" "$SCAN_ENGINE_TIMEOUT_MS" "0"
}

# Run a TCP port scan across SCAN_TARGETS using PORTS[].
# Args: threads (default 1), timeout_ms (default 1000)
run_tcp_port_scan() {
  local threads="${1:-1}"
  local timeout_ms="${2:-1000}"

  SCAN_ENGINE_FINDINGS=0
  SCAN_ENGINE_TIMEOUT_MS="$timeout_ms"
  declare -g -A SCAN_ENGINE_DEDUP=()

  (( ${#SCAN_TARGETS[@]} > 0 )) || {
    echo "run_tcp_port_scan: SCAN_TARGETS is empty" >&2
    return 1
  }
  (( ${#PORTS[@]} > 0 )) || {
    echo "run_tcp_port_scan: PORTS catalog is empty" >&2
    return 1
  }

  PORT_CATALOG_STR="$(printf '%s\n' "${PORTS[@]}")"
  export PORT_CATALOG_STR SCAN_ENGINE_TIMEOUT_MS

  local total=${#SCAN_TARGETS[@]}

  if (( threads <= 1 )); then
    scan_engine_reset_progress 2>/dev/null || scan_engine_progress_start_epoch=0
    local processed=0 host
    for host in "${SCAN_TARGETS[@]}"; do
      processed=$((processed + 1))
      if [[ -n "${SCAN_ENGINE_PROGRESS_HOOK:-}" ]]; then
        "$SCAN_ENGINE_PROGRESS_HOOK" "$host" "$processed" "$total"
      fi
      scan_engine_probe_host "$host" "$timeout_ms" "1"
    done
    return 0
  fi

  export -f scan_engine_parallel_worker scan_engine_probe_host scan_engine_emit_finding
  export -f scan_engine_default_finding_hook test_tcp_port export_scan_report_append
  export SCAN_ENGINE_FINDING_HOOK

  scan_engine_reset_progress 2>/dev/null || scan_engine_progress_start_epoch=0
  local queued=0 completed=0 host
  for host in "${SCAN_TARGETS[@]}"; do
    while (( $(jobs -pr | wc -l) >= threads )); do
      if wait -n 2>/dev/null; then
        completed=$((completed + 1))
        if [[ -n "${SCAN_ENGINE_PROGRESS_HOOK:-}" ]]; then
          "$SCAN_ENGINE_PROGRESS_HOOK" "" "$completed" "$total"
        fi
      else
        break
      fi
    done
    scan_engine_parallel_worker "$host" &
    queued=$((queued + 1))
  done
  while (( completed < queued )); do
    if wait -n 2>/dev/null; then
      completed=$((completed + 1))
      if [[ -n "${SCAN_ENGINE_PROGRESS_HOOK:-}" ]]; then
        "$SCAN_ENGINE_PROGRESS_HOOK" "" "$completed" "$total"
      fi
    else
      wait 2>/dev/null || true
      completed=$queued
    fi
  done
  printf '\n'
}
