#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mapfile -t scripts < <(find "$ROOT/scanners/bas" -type f -name '*.sh')
[ "${#scripts[@]}" -gt 0 ]
for script in "${scripts[@]}"; do bash -n "$script"; done
for file in docs/sectors/bas/CISA-Reference.md docs/sectors/bas/Threat-Intelligence.md docs/sectors/bas/threat-model.md docs/sectors/bas/sample-report.md; do
  [ -f "$ROOT/$file" ]
done
printf 'BAS scanner validation passed for %s Bash file(s).\n' "${#scripts[@]}"
