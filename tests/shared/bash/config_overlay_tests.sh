#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 1; }
pip install pyyaml -q 2>/dev/null || true

OVERLAY="$(mktemp --suffix=.yaml)"
trap 'rm -f "$OVERLAY"' EXIT
cat > "$OVERLAY" <<'YAML'
remote_access_ports:
  - port: 3390
    label: "Overlay test port"
    severity: HIGH
    context_key: RDP
threat_context:
  RDP: "Overlay threat context override"
YAML

BASE="${ROOT}/config/sectors/water.json"
MERGED="$(python3 "${ROOT}/scripts/config/merge_overlay.py" "$BASE" "$OVERLAY")"

echo "$MERGED" | python3 -c "
import json, sys
data = json.load(sys.stdin)
ports = {p['port'] for p in data['remote_access_ports']}
assert 3390 in ports, 'overlay port 3390 missing'
assert data['threat_context']['RDP'] == 'Overlay threat context override'
print('Config overlay tests passed.')
"

# Bash loader path with overlay export
export SECTOR_CONFIG_OVERLAY="$OVERLAY"
# shellcheck source=../../../scanners/_shared/load_sector_config.sh
source "${ROOT}/scanners/_shared/load_sector_config.sh"
initialize_water_config
found=0
for entry in "${REMOTE_ACCESS_PORTS[@]}"; do
  [[ "${entry%%|*}" == "3390" ]] && found=1
done
(( found == 1 )) || { echo "initialize_water_config did not load overlay port 3390" >&2; exit 1; }
echo "Bash config overlay loader passed."
