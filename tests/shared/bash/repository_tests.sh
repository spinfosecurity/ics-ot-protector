#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCANNERS="${ROOT}/scanners"
SECTORS=(water energy-grid bas rail)

for sector in "${SECTORS[@]}"; do
  [[ -d "${SCANNERS}/${sector}" ]] || { echo "Missing sector directory: ${sector}" >&2; exit 1; }
  mapfile -t ps1_files < <(find "${SCANNERS}/${sector}" -type f -name '*.ps1')
  mapfile -t sh_files < <(find "${SCANNERS}/${sector}" -type f -name '*.sh')
  [[ "${#ps1_files[@]}" -gt 0 ]] || { echo "No PowerShell scanner in ${sector}" >&2; exit 1; }
  [[ "${#sh_files[@]}" -gt 0 ]] || { echo "No Bash scanner in ${sector}" >&2; exit 1; }
  for script in "${sh_files[@]}"; do bash -n "$script"; done
done

for file in CHANGELOG.md CODE_OF_CONDUCT.md docs/safe-operation.md docs/threat-model.md docs/sample-report.md; do
  [[ -f "${ROOT}/${file}" ]] || { echo "Missing required file: ${file}" >&2; exit 1; }
done

for sector in "${SECTORS[@]}"; do
  [[ -f "${ROOT}/docs/sectors/${sector}/threat-model.md" ]] || { echo "Missing sector doc: ${sector}/threat-model.md" >&2; exit 1; }
  [[ -f "${ROOT}/docs/sectors/${sector}/sample-report.md" ]] || { echo "Missing sector doc: ${sector}/sample-report.md" >&2; exit 1; }
  [[ -f "${ROOT}/config/sectors/${sector}.yaml" ]] || { echo "Missing config: ${sector}.yaml" >&2; exit 1; }
  [[ -f "${ROOT}/config/sectors/${sector}.json" ]] || { echo "Missing config: ${sector}.json" >&2; exit 1; }
done

grep -Eiq 'authorized|permission' "${ROOT}/README.md"
printf 'Monorepo validation passed for %d sector scanner(s).\n' "${#SECTORS[@]}"
