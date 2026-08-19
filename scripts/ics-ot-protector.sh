#!/usr/bin/env bash
# Unified launcher for ICS OT Protector sector scanners.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
ICS OT Protector — unified sector scanner launcher

Usage:
  ./scripts/ics-ot-protector.sh <sector> [scanner args...]

Sectors:
  water         Water Utility Protector (WUP WUP) — interactive
  energy-grid   Energy Grid Protector (EGP) — CLI
  bas           BAS Guardian — interactive
  rail          Rail-OT-Protector (ROP) — CLI

Examples:
  ./scripts/ics-ot-protector.sh water
  ./scripts/ics-ot-protector.sh energy-grid -s 192.168.10.0/24
  ./scripts/ics-ot-protector.sh bas
  ./scripts/ics-ot-protector.sh rail 10.10.20.0/24
EOF
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

SECTOR="$1"
shift

case "$SECTOR" in
  water)
    exec bash "$ROOT/scanners/water/bash/WUP-WUP.sh" "$@"
    ;;
  energy-grid)
    exec bash "$ROOT/scanners/energy-grid/bash/EGP.sh" "$@"
    ;;
  bas)
    exec bash "$ROOT/scanners/bas/bash/BAS-Guardian.sh" "$@"
    ;;
  rail)
    exec bash "$ROOT/scanners/rail/bash/ROP.sh" "$@"
    ;;
  *)
    echo "Unknown sector: $SECTOR" >&2
    usage >&2
    exit 1
    ;;
esac
