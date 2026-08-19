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
