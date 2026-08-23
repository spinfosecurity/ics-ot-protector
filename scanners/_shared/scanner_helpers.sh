#!/usr/bin/env bash
# Shared subnet helpers for Bash scanners.
# Source this file; do not execute directly.

get_network_prefix() {
  echo "$1" | cut -d'/' -f1 | cut -d'.' -f1-3
}

get_subnet_hosts() {
  local cidr="$1"
  local prefix
  prefix="$(get_network_prefix "$cidr")"
  seq 1 254 | while read -r i; do
    echo "${prefix}.${i}"
  done
}

# Returns 0 if TCP connect succeeds within timeout_sec (default 1).
test_tcp_port() {
  local ip="$1"
  local port="$2"
  local timeout_sec="${3:-1}"
  timeout "$timeout_sec" bash -c "exec 3<>/dev/tcp/${ip}/${port}" 2>/dev/null
}

# Validate IPv4 CIDR notation (prefix /8 through /32).
validate_cidr() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]
}

ip2int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int2ip() {
  local n=$1
  printf '%d.%d.%d.%d\n' \
    $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) \
    $(( (n >>  8) & 255 )) $((  n        & 255 ))
}

# Expand a CIDR to host addresses (excludes network/broadcast for prefixes < 31).
# Prefixes below /8 are rejected as too broad for safe scanning.
expand_cidr() {
  local cidr="$1" ip prefix ip_int mask network size first last cur
  ip="${cidr%/*}"
  prefix="${cidr#*/}"
  (( prefix >= 8 )) || {
    printf '[WARN] Skipping prefix /%s — too broad for safe scan\n' "$prefix" >&2
    return 0
  }
  ip_int=$(ip2int "$ip")
  if (( prefix == 32 )); then
    mask=4294967295
  else
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  fi
  network=$(( ip_int & mask ))
  size=$(( 1 << (32 - prefix) ))
  if (( prefix >= 31 )); then
    first=$network
    last=$network
  else
    first=$(( network + 1 ))
    last=$(( network + size - 2 ))
  fi
  for (( cur=first; cur<=last; cur++ )); do
    int2ip "$cur"
  done
}

# Build a deduplicated host list from comma-separated CIDRs into SCAN_TARGETS[].
build_scan_targets() {
  local subnets_csv="$1"
  declare -g -a SCAN_TARGETS=()
  declare -g -A SCAN_TARGET_SEEN=()
  local subnet subnet_arr=() ip
  IFS=',' read -r -a subnet_arr <<< "$subnets_csv"
  for subnet in "${subnet_arr[@]}"; do
    subnet="${subnet// /}"
    [[ -z "$subnet" ]] && continue
    validate_cidr "$subnet" || continue
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      if [[ -z "${SCAN_TARGET_SEEN[$ip]+x}" ]]; then
        SCAN_TARGETS+=("$ip")
        SCAN_TARGET_SEEN[$ip]=1
      fi
    done < <(expand_cidr "$subnet")
  done
}

# Return host count for a CIDR without enumerating addresses.
count_hosts_in_cidr() {
  local cidr="$1" ip prefix ip_int mask network size
  ip="${cidr%/*}"
  prefix="${cidr#*/}"
  (( prefix >= 8 && prefix <= 32 )) || return 1
  ip_int=$(ip2int "$ip")
  if (( prefix == 32 )); then
    echo 1
    return 0
  fi
  mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  network=$(( ip_int & mask ))
  size=$(( 1 << (32 - prefix) ))
  if (( prefix >= 31 )); then
    echo 1
  else
    echo $(( size - 2 ))
  fi
}

# Sum deduplicated host counts for comma-separated CIDRs.
count_scan_targets() {
  local subnets_csv="$1"
  declare -A seen=()
  local subnet subnet_arr=() ip total=0
  IFS=',' read -r -a subnet_arr <<< "$subnets_csv"
  for subnet in "${subnet_arr[@]}"; do
    subnet="${subnet// /}"
    [[ -z "$subnet" ]] && continue
    validate_cidr "$subnet" || continue
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      if [[ -z "${seen[$ip]+x}" ]]; then
        seen[$ip]=1
        total=$((total + 1))
      fi
    done < <(expand_cidr "$subnet")
  done
  echo "$total"
}
