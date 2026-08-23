#!/usr/bin/env bash
# Pre-flight dependency and scan-scope validation for Bash scanners.
# Source this file; do not execute directly.

PREFLIGHT_WARN_HOSTS=1024
PREFLIGHT_FORCE_HOSTS=4096

preflight_check_dependencies() {
  local missing=()
  command -v jq >/dev/null 2>&1 || missing+=("jq")
  command -v timeout >/dev/null 2>&1 || missing+=("timeout")
  if (( ${#missing[@]} > 0 )); then
    echo "Missing required dependencies: ${missing[*]}" >&2
    echo "Install jq and coreutils (timeout) before running scans." >&2
    return 1
  fi
  return 0
}

# Validate comma-separated CIDRs before scanning.
# Sets PREFLIGHT_HOST_COUNT and PREFLIGHT_SUBNETS_VALIDATED[].
# Use FORCE_LARGE_SCAN=1 to allow scopes above PREFLIGHT_FORCE_HOSTS.
preflight_validate_scan_scope() {
  local subnets_csv="$1"
  local force="${2:-0}"
  PREFLIGHT_HOST_COUNT=0
  PREFLIGHT_SUBNETS_VALIDATED=()
  PREFLIGHT_WARNINGS=()

  local subnet subnet_arr=() prefix host_count total=0
  IFS=',' read -r -a subnet_arr <<< "$subnets_csv"
  for subnet in "${subnet_arr[@]}"; do
    subnet="${subnet// /}"
    [[ -z "$subnet" ]] && continue
    if ! validate_cidr "$subnet"; then
      echo "Invalid CIDR notation: $subnet (expected x.x.x.x/n)" >&2
      return 1
    fi
    prefix="${subnet#*/}"
    if (( prefix < 8 )); then
      echo "Subnet $subnet is too broad (prefix /$prefix). Minimum allowed prefix is /8." >&2
      return 1
    fi
    if (( prefix <= 16 && force != 1 )); then
      echo "Subnet $subnet spans a large address space (/ $prefix)." >&2
      echo "Re-run with --force to acknowledge scanning $(count_hosts_in_cidr "$subnet") hosts." >&2
      return 1
    fi
    host_count=$(count_hosts_in_cidr "$subnet")
    total=$((total + host_count))
    if (( prefix <= 20 )); then
      PREFLIGHT_WARNINGS+=("Large subnet $subnet (/ $prefix, ~$host_count hosts)")
    fi
    PREFLIGHT_SUBNETS_VALIDATED+=("$subnet")
  done

  if (( ${#PREFLIGHT_SUBNETS_VALIDATED[@]} == 0 )); then
    echo "No valid CIDR targets in: $subnets_csv" >&2
    return 1
  fi

  # Deduplicated count (overlapping CIDRs)
  PREFLIGHT_HOST_COUNT=$(count_scan_targets "$subnets_csv")

  if (( PREFLIGHT_HOST_COUNT > PREFLIGHT_FORCE_HOSTS && force != 1 )); then
    echo "Scan scope is $PREFLIGHT_HOST_COUNT unique hosts (limit ${PREFLIGHT_FORCE_HOSTS} without --force)." >&2
    return 1
  fi
  if (( PREFLIGHT_HOST_COUNT > PREFLIGHT_WARN_HOSTS )); then
    PREFLIGHT_WARNINGS+=("Scan will probe $PREFLIGHT_HOST_COUNT unique hosts")
  fi

  local warn
  for warn in "${PREFLIGHT_WARNINGS[@]}"; do
    printf '[WARN] %s\n' "$warn" >&2
  done

  return 0
}

preflight_print_summary() {
  local sector="$1" ports="$2" threads="$3" timeout_ms="$4"
  printf '[INFO] Pre-flight OK | Sector: %s | Hosts: %s | Ports: %s | Probes: ~%s | Threads: %s | Timeout: %sms\n' \
    "$sector" "$PREFLIGHT_HOST_COUNT" "$ports" "$(( PREFLIGHT_HOST_COUNT * ports ))" "$threads" "$timeout_ms"
}
