#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
python3 "${ROOT}/scripts/config/compile_configs.py"
echo "Config validation passed."
