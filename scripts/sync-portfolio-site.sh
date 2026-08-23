#!/usr/bin/env bash
# Copy portfolio-site/ into a local clone of spinfosecurity.github.io and push.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/portfolio-site"
DEST="${1:-}"

if [[ -z "$DEST" ]]; then
  echo "Usage: sync-portfolio-site.sh /path/to/spinfosecurity.github.io" >&2
  exit 1
fi

[[ -d "$SRC" ]] || { echo "Missing $SRC" >&2; exit 1; }
[[ -d "$DEST/.git" ]] || { echo "Not a git repo: $DEST" >&2; exit 1; }

shopt -s dotglob nullglob
for item in "$SRC"/*; do
  base="$(basename "$item")"
  [[ "$base" == "README.md" ]] && continue
  cp -a "$item" "$DEST/"
done

echo "Synced to $DEST — review with 'git status' and commit when ready."
