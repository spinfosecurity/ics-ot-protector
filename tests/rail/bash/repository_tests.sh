#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mapfile -t scripts < <(find "$ROOT/scanners/rail" -type f -name '*.sh')
[ "${#scripts[@]}" -gt 0 ]
for script in "${scripts[@]}"; do bash -n "$script"; done
for file in docs/sectors/rail/CISA-Reference.md docs/sectors/rail/Threat-Intelligence.md docs/sectors/rail/threat-model.md docs/sectors/rail/sample-report.md; do
  [ -f "$ROOT/$file" ]
done
printf 'Rail scanner validation passed for %s Bash file(s).\n' "${#scripts[@]}"
