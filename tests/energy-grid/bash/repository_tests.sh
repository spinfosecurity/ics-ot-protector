#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mapfile -t scripts < <(find "$ROOT/scanners/energy-grid" -type f -name '*.sh')
[ "${#scripts[@]}" -gt 0 ]
for script in "${scripts[@]}"; do bash -n "$script"; done
for file in docs/sectors/energy-grid/threat-model.md docs/sectors/energy-grid/sample-report.md; do
  [ -f "$ROOT/$file" ]
done
printf 'Energy-grid scanner validation passed for %s Bash file(s).\n' "${#scripts[@]}"
