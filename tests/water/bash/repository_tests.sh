#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mapfile -t scripts < <(find "$ROOT/scanners/water" -type f -name '*.sh')
[ "${#scripts[@]}" -gt 0 ]
for script in "${scripts[@]}"; do bash -n "$script"; done
for file in docs/sectors/water/CISA-Reference.md docs/sectors/water/Threat-Intelligence.md docs/sectors/water/threat-model.md docs/sectors/water/sample-report.md; do
  [ -f "$ROOT/$file" ]
done
printf 'Water scanner validation passed for %s Bash file(s).\n' "${#scripts[@]}"
