#!/usr/bin/env bash
# Shared sector configuration loader for Bash scanners.
# Reads compiled JSON from config/sectors/{sector}.json (source: .yaml).

get_repo_root() {
  if [[ -n "${REPO_ROOT:-}" ]]; then
    printf '%s' "$REPO_ROOT"
    return
  fi
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  printf '%s' "$REPO_ROOT"
}

_load_config_json() {
  local sector="$1"
  local root
  root="$(get_repo_root)"
  local path="${root}/config/sectors/${sector}.json"
  if [[ ! -f "$path" ]]; then
    echo "Sector config not found: ${path} (run scripts/config/compile_configs.py)" >&2
    return 1
  fi
  python3 - "$path" <<'PY'
import json, sys
print(json.dumps(json.load(open(sys.argv[1], encoding='utf-8'))))
PY
}

initialize_water_config() {
  local json
  json="$(_load_config_json water)" || return 1
  SCRIPT_VERSION="$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['metadata']['version'])" <<< "$json")"
  SCRIPT_REFERENCE="$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['metadata']['reference'])" <<< "$json")"
  REMOTE_ACCESS_PORTS=()
  OT_PROTOCOL_PORTS=()
  declare -gA THREAT_CONTEXT=()
  while IFS= read -r line; do REMOTE_ACCESS_PORTS+=("$line"); done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['remote_access_ports']:
    print(f\"{p['port']}|{p['label']}|{p['severity']}\")
" <<< "$json")
  while IFS= read -r line; do OT_PROTOCOL_PORTS+=("$line"); done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['ot_protocol_ports']:
    print(f\"{p['port']}|{p['label']}\")
" <<< "$json")
  while IFS='=' read -r k v; do THREAT_CONTEXT["$k"]="$v"; done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for k,v in d['threat_context'].items():
    print(f'{k}={v}')
" <<< "$json")
}

initialize_energy_grid_config() {
  local json
  json="$(_load_config_json energy-grid)" || return 1
  declare -gA cve_checks=() remote_access_ports=() ics_ports=()
  while IFS='|' read -r id rest; do
    cve_checks["$id"]="$rest"
  done < <(python3 -c "
import json,sys
d=json.load(sys.stdin)
for cid,c in d['cve_checks'].items():
    ports=','.join(str(p) for p in c['ports'])
    print(f\"{cid}|{ports}|{c['description']}|{c['severity']}|{c['remediation']}\")
" <<< "$json")
  while IFS='|' read -r port rest; do
    remote_access_ports["$port"]="$rest"
  done < <(python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['remote_access_ports']:
    print(f\"{p['port']}|{p['name']}|{p['severity']}|{p['description']}\")
" <<< "$json")
  while IFS='|' read -r port rest; do
    ics_ports["$port"]="$rest"
  done < <(python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['ics_ports']:
    print(f\"{p['port']}|{p['name']}|{p['severity']}|{p['description']}\")
" <<< "$json")
}

build_energy_grid_port_catalog() {
  local mode="${1:-full}"
  PORTS=()
  local cve_id ports_str description severity remediation port_list port
  for cve_id in "${!cve_checks[@]}"; do
    IFS='|' read -r ports_str description severity remediation <<< "${cve_checks[$cve_id]}"
    IFS=',' read -r -a port_list <<< "$ports_str"
    for port in "${port_list[@]}"; do
      PORTS+=("${port}|${cve_id}|${severity}|CVE|${description}|${remediation}")
    done
  done
  if [[ "$mode" != "cve_only" ]]; then
    local name
    for port in "${!remote_access_ports[@]}"; do
      IFS='|' read -r name severity description <<< "${remote_access_ports[$port]}"
      PORTS+=("${port}|REMOTE-ACCESS:${name}|${severity}|RemoteAccess|${description}|See docs/CISA-Reference.md")
    done
    for port in "${!ics_ports[@]}"; do
      IFS='|' read -r name severity description <<< "${ics_ports[$port]}"
      PORTS+=("${port}|ICS-PROTOCOL:${name}|${severity}|ICS|${description}|See docs/Threat-Intelligence.md")
    done
  fi
}

initialize_bas_config() {
  local json
  json="$(_load_config_json bas)" || return 1
  SCRIPT_VERSION="$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['metadata']['version'])" <<< "$json")"
  SCRIPT_TAGLINE="$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['metadata']['tagline'])" <<< "$json")"
  REFERENCE="$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d['metadata']['reference'])" <<< "$json")"
  declare -gA CRITICAL_BAS_PORTS=() REMOTE_ACCESS_PORTS=() THREAT_CONTEXT=() VENDOR_ALERT_PORTS=()
  while IFS='|' read -r port label; do CRITICAL_BAS_PORTS["$port"]="$label"; done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['bas_protocol_ports']:
    print(f\"{p['port']}|{p['label']}\")
" <<< "$json")
  while IFS='|' read -r port label; do REMOTE_ACCESS_PORTS["$port"]="$label"; done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['remote_access_ports']:
    print(f\"{p['port']}|{p['label']}\")
" <<< "$json")
  while IFS='=' read -r k v; do THREAT_CONTEXT["$k"]="$v"; done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for k,v in d['threat_context'].items():
    print(f'{k}={v}')
" <<< "$json")
  while IFS='|' read -r port rest; do VENDOR_ALERT_PORTS["$port"]="$rest"; done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for a in d['vendor_alerts']:
    print(f\"{a['port']}|{a['vendor']}|{a['cve']}|{a['cvss']}|{a['description']}|{a['action']}\")
" <<< "$json")
}

initialize_rail_config() {
  local json
  json="$(_load_config_json rail)" || return 1
  RAIL_CONFIG_JSON="$json"
}

build_rail_port_catalog() {
  PORTS=()
  local filter="${1:-all}"
  while IFS= read -r line; do PORTS+=("$line"); done < <(
    python3 -c "
import json,sys
d=json.load(sys.stdin)
flt=sys.argv[1]
for e in d['port_catalog']:
    if flt == 'eothot' and e['category'] != 'EotHot':
        continue
    print(f\"{e['port']}|{e['name']}|{e['severity']}|{e['category']}|{e['description']}\")
" <<< "$RAIL_CONFIG_JSON" "$filter")
}
