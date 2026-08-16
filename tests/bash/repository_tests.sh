#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mapfile -t scripts < <(find "$ROOT/scripts" -type f -name '*.sh')
[ "${#scripts[@]}" -gt 0 ]
for script in "${scripts[@]}"; do bash -n "$script"; done
for file in CHANGELOG.md CODE_OF_CONDUCT.md docs/safe-operation.md docs/threat-model.md docs/sample-report.md; do [ -f "$ROOT/$file" ]; done
grep -Eiq 'authorized|permission' "$ROOT/README.md"
printf 'Repository validation passed for %s Bash file(s).\n' "${#scripts[@]}"
