#!/usr/bin/env bash
# Backward-compatible launcher — canonical path: scanners/water/bash/WUP-WUP.sh
set -euo pipefail
CANONICAL="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scanners/water/bash/WUP-WUP.sh"
if [[ ! -f "$CANONICAL" ]]; then
  echo "Canonical scanner not found: $CANONICAL" >&2
  exit 1
fi
exec bash "$CANONICAL" "$@"
