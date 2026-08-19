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
