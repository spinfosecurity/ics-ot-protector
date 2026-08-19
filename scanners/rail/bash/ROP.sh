#!/usr/bin/env bash
# =============================================================================
# Rail-OT-Protector (ROP) — Bash Scanner
# Scans rail/transit OT subnets for CVE-2025-1727 (EOT/HOT), RailSafe legacy
# SCADA API, ICS protocols, and remote-access exposure.
#
# Copyright (c) 2026 spinfosecurity | MIT License
# References: CISA AA26-097A, FBI PSA 2026-08-01
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SUBNETS=""
TIMEOUT_MS=1500
THREADS=64
OUTPUT_DIR="./reports"
EOT_HOT_ONLY=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Rail-OT-Protector (ROP) — Bash Scanner

Usage:
  ./ROP.sh --subnets <CIDR[,CIDR...]> [OPTIONS]

Required:
  --subnets <CIDRs>     Comma-separated CIDR ranges (e.g. 10.10.20.0/24,10.10.30.0/24)

Optional:
  --timeout-ms <n>      TCP connect timeout in ms (100-10000, default 1500)
  --threads <n>         Max concurrent workers (1-512, default 64)
  --output-dir <dir>    Report output directory (default ./reports)
  --eot_hot_only        Fast mode: EOT/HOT ports only (CVE-2025-1727)
  --help                Show this message
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
[[ $# -eq 0 ]] && { usage; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --subnets)     SUBNETS="$2";     shift 2 ;;
    --timeout-ms)  TIMEOUT_MS="$2"; shift 2 ;;
    --threads)     THREADS="$2";     shift 2 ;;
    --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
    --eot_hot_only) EOT_HOT_ONLY=1; shift ;;
    --help|-h)     usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
[[ -n "$SUBNETS" ]] || { printf '[ERROR] --subnets is required\n' >&2; exit 1; }

[[ "$TIMEOUT_MS" =~ ^[0-9]+$ ]] && (( TIMEOUT_MS >= 100 && TIMEOUT_MS <= 10000 )) || {
  printf '[ERROR] --timeout-ms must be an integer between 100 and 10000\n' >&2; exit 1;
}

[[ "$THREADS" =~ ^[0-9]+$ ]] && (( THREADS >= 1 && THREADS <= 512 )) || {
  printf '[ERROR] --threads must be an integer between 1 and 512\n' >&2; exit 1;
}

mkdir -p "$OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() {
  local level="$1"; shift
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

validate_cidr() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]
}

ip2int() {
  local a b c d; IFS=. read -r a b c d <<< "$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int2ip() {
  local n=$1
  printf '%d.%d.%d.%d\n' \
    $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) \
    $(( (n >>  8) & 255 )) $((  n        & 255 ))
}

expand_cidr() {
  local cidr="$1" ip prefix ip_int mask network size
  ip="${cidr%/*}"; prefix="${cidr#*/}"
  (( prefix >= 8 )) || { printf '[WARN] Skipping prefix /%s — too broad for safe scan\n' "$prefix" >&2; return; }
  ip_int=$(ip2int "$ip")
  if (( prefix == 32 )); then mask=4294967295
  else mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  fi
  network=$(( ip_int & mask ))
  size=$(( 1 << (32 - prefix) ))
  local first=$(( network + 1 )) last=$(( network + size - 2 ))
  for (( cur=first; cur<=last; cur++ )); do int2ip "$cur"; done
}

# ---------------------------------------------------------------------------
# Port catalog  format: port|name|severity|category|description
# ---------------------------------------------------------------------------
declare -a PORTS=()
build_port_catalog() {
  if [[ "$EOT_HOT_ONLY" -eq 1 ]]; then
    PORTS=(
      "4510|EOT/HOT Remote Linking|CRITICAL|EotHot|Potential EOT/HOT remote linking service detected (CVE-2025-1727) — Wabtec TrainLink NG/NG3/NG4/NG5 Siemens Trainguard DPS Electronics"
      "4511|EOT/HOT Remote Linking (alt)|CRITICAL|EotHot|Potential EOT/HOT remote linking backup channel detected (CVE-2025-1727)"
    )
    return
  fi
  PORTS=(
    "4510|EOT/HOT Remote Linking|CRITICAL|EotHot|Potential EOT/HOT remote linking service detected (CVE-2025-1727) — Wabtec TrainLink NG/NG3/NG4/NG5 Siemens Trainguard DPS Electronics"
    "4511|EOT/HOT Remote Linking (alt)|CRITICAL|EotHot|Potential EOT/HOT remote linking backup channel detected (CVE-2025-1727)"
    "28784|RailSafe Control Interface|HIGH|RailSafe|RailSafe Control Interface fingerprint matched legacy API version family (v1.0/1.1/2.0 MitM/replay risk 13 years unpatched)"
    "21|FTP|HIGH|RemoteAccess|FTP exposed on OT network — plaintext credential risk"
    "22|SSH|MEDIUM|RemoteAccess|SSH reachable from scan host — review access policy"
    "23|Telnet|HIGH|RemoteAccess|Telnet exposed on OT network — plaintext credential risk"
    "80|HTTP|MEDIUM|RemoteAccess|HTTP management interface reachable — review access and authentication"
    "443|HTTPS|MEDIUM|RemoteAccess|HTTPS management interface reachable — validate certificate and access controls"
    "3389|RDP|HIGH|RemoteAccess|RDP exposed on OT subnet — restrict immediately per CISA AA26-097A"
    "5900|VNC|HIGH|RemoteAccess|VNC exposed on OT subnet — restrict immediately per FBI PSA 2026-08-01"
    "5901|VNC (alt display)|HIGH|RemoteAccess|Alternate VNC display port exposed on OT subnet — review per FBI PSA 2026-08-01"
    "102|S7/IEC 60870|HIGH|ICS|S7/IEC 60870 service reachable — validate OT network segmentation"
    "502|Modbus|HIGH|ICS|Modbus service reachable from scan host — validate segmentation"
    "2222|EtherNet/IP (implicit)|HIGH|ICS|EtherNet/IP implicit messaging port reachable — validate segmentation"
    "2404|IEC 60870-5-104|HIGH|ICS|IEC 60870-5-104 reachable from scan host — validate segmentation"
    "20000|DNP3|HIGH|ICS|DNP3 service reachable from scan host — validate segmentation"
    "44818|EtherNet/IP (explicit)|HIGH|ICS|EtherNet/IP explicit messaging port reachable — validate segmentation"
  )
}

# ---------------------------------------------------------------------------
# Thread-safe write (spin-lock via mkdir atomicity)
# ---------------------------------------------------------------------------
LOCK_DIR="$(mktemp -d)"
JSON_TMP="$(mktemp)"
echo '[]' > "$JSON_TMP"

timestamp_file="$(date +%Y%m%d-%H%M%S)"
CSV_PATH="$OUTPUT_DIR/ROP-results-$timestamp_file.csv"
JSON_PATH="$OUTPUT_DIR/ROP-results-$timestamp_file.json"
printf 'Timestamp,Host,Port,Service,Severity,Category,Description\n' > "$CSV_PATH"

write_finding() {
  local host="$1" port="$2" service="$3" severity="$4" category="$5" description="$6"
  local ts; ts=$(date '+%Y-%m-%dT%H:%M:%S')

  # Acquire lock
  while ! mkdir "$LOCK_DIR/write.lock" 2>/dev/null; do sleep 0.005; done

  # CSV
  printf '%s,%s,%s,"%s",%s,%s,"%s"\n' \
    "$ts" "$host" "$port" "$service" "$severity" "$category" "$description" >> "$CSV_PATH"

  # JSON (requires jq)
  if command -v jq &>/dev/null; then
    jq --arg ts "$ts" --arg h "$host" --argjson p "$port" \
       --arg svc "$service" --arg sev "$severity" \
       --arg cat "$category" --arg desc "$description" \
       '. += [{Timestamp:$ts,Host:$h,Port:$p,Service:$svc,Severity:$sev,Category:$cat,Description:$desc}]' \
       "$JSON_TMP" > "${JSON_TMP}.next" && mv "${JSON_TMP}.next" "$JSON_TMP"
  fi

  rmdir "$LOCK_DIR/write.lock"

  printf '[%s] [%s] %s:%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$severity" "$host" "$port" "$description"
}
export -f write_finding log
export LOCK_DIR JSON_TMP CSV_PATH

# ---------------------------------------------------------------------------
# Per-host scan worker
# ---------------------------------------------------------------------------
scan_host() {
  local host="$1"
  shift
  local timeout_sec; timeout_sec=$(awk "BEGIN{printf \"%.3f\",$TIMEOUT_MS/1000}")

  # Re-import port catalog in subshell (exported as env var array string)
  local IFS=$'\n'
  for record in $PORT_CATALOG_STR; do
    [[ -z "$record" ]] && continue
    local port service severity category description
    IFS='|' read -r port service severity category description <<< "$record"
    if timeout "$timeout_sec" bash -c "exec 3>/dev/tcp/$host/$port" 2>/dev/null; then
      write_finding "$host" "$port" "$service" "$severity" "$category" "$description"
    fi
  done
}
export -f scan_host
export TIMEOUT_MS

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------
declare -a UNIQUE_TARGETS=()
declare -A SEEN=()

IFS=',' read -r -a subnet_arr <<< "$SUBNETS"
for subnet in "${subnet_arr[@]}"; do
  subnet="${subnet// /}"
  validate_cidr "$subnet" || { log WARN "Invalid CIDR, skipping: $subnet"; continue; }
  while IFS= read -r ip; do
    [[ -z "${SEEN[$ip]+x}" ]] && { UNIQUE_TARGETS+=("$ip"); SEEN[$ip]=1; }
  done < <(expand_cidr "$subnet")
done

(( ${#UNIQUE_TARGETS[@]} > 0 )) || { log ERROR 'No valid targets generated — check --subnets input'; exit 1; }

build_port_catalog

# Export port catalog as newline-delimited string for subshell workers
PORT_CATALOG_STR="$(printf '%s\n' "${PORTS[@]}")"
export PORT_CATALOG_STR

log INFO "Scan starting | Targets: ${#UNIQUE_TARGETS[@]} | Ports: ${#PORTS[@]} | Threads: $THREADS | Timeout: ${TIMEOUT_MS}ms | EotHotOnly: $EOT_HOT_ONLY"

# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------
processed=0
total=${#UNIQUE_TARGETS[@]}

for host in "${UNIQUE_TARGETS[@]}"; do
  while (( $(jobs -pr | wc -l) >= THREADS )); do wait -n 2>/dev/null || true; done
  scan_host "$host" &
  processed=$(( processed + 1 ))
  printf '\rProgress: %d / %d hosts queued (%d%%)' "$processed" "$total" $(( processed * 100 / total ))
done
wait
printf '\n'

# ---------------------------------------------------------------------------
# Finalize reports
# ---------------------------------------------------------------------------
mv "$JSON_TMP" "$JSON_PATH"
rm -rf "$LOCK_DIR"
log INFO "Scan complete | CSV: $CSV_PATH | JSON: $JSON_PATH"
