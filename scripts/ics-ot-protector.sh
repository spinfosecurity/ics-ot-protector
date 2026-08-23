#!/usr/bin/env bash
# Unified launcher for ICS OT Protector sector scanners.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
ICS OT Protector — unified sector scanner launcher

Usage:
  ./scripts/ics-ot-protector.sh <sector> [scanner args...]
  ./scripts/ics-ot-protector.sh scan --sector <name> --subnets <CIDR[,CIDR...]> [options]

Sectors:
  water         Water Utility Protector (WUP WUP) — interactive
  energy-grid   Energy Grid Protector (EGP) — CLI
  bas           BAS Guardian — interactive
  rail          Rail-OT-Protector (ROP) — CLI

Scan mode (non-interactive, all sectors):
  --sector <name>       water | energy-grid | bas | rail
  --subnets <CIDRs>     Comma-separated target ranges
  --threads <n>         Concurrent workers (default 64)
  --timeout-ms <n>      TCP timeout in ms (default 1500)
  --output-dir <dir>    Report directory (default ./reports)
  --cve-only            Energy-grid CVE-only fast mode
  --eot-hot-only        Rail EOT/HOT-only fast mode
  --force               Acknowledge large scan scope (/17-/8 or >4096 hosts)
  --no-csv              Skip CSV export (JSON is always written)

Examples:
  ./scripts/ics-ot-protector.sh water
  ./scripts/ics-ot-protector.sh energy-grid -s 192.168.10.0/24
  ./scripts/ics-ot-protector.sh scan --sector rail --subnets 10.10.20.0/24
  ./scripts/ics-ot-protector.sh scan --sector energy-grid --subnets 192.168.10.0/24 --cve-only
EOF
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$1" == "scan" ]]; then
  shift
  exec bash "$ROOT/scanners/_shared/run_sector_scan.sh" "$@"
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
