#!/usr/bin/env bash
# Archive legacy standalone scanner repos and rename the monorepo.
#
# Requires: gh CLI authenticated with org-admin permissions on spinfosecurity
# Usage:    ./scripts/admin/archive-legacy-repos.sh [--skip-rename]
#
set -euo pipefail

ORG="spinfosecurity"
MONOREPO="${ORG}/water-utility-protector"
NEW_NAME="ics-ot-protector"
MONOREPO_URL="https://github.com/${ORG}/${NEW_NAME}"

LEGACY_REPOS=(
  "Energy-Grid-Protector:energy-grid"
  "BAS-Guardian:bas"
  "Rail-OT-Protector:rail"
)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SKIP_RENAME=false
if [[ "${1:-}" == "--skip-rename" ]]; then
  SKIP_RENAME=true
fi

echo "==> Checking gh authentication..."
gh auth status

push_archive_readme() {
  local repo="$1"
  local notice_dir="$2"
  local tmp="${WORK}/${repo}"

  echo ""
  echo "==> Updating README for ${ORG}/${repo}..."
  git clone --depth 1 "https://github.com/${ORG}/${repo}.git" "$tmp"
  cp "${ROOT}/docs/archive-notices/${notice_dir}/README.md" "${tmp}/README.md"
  pushd "$tmp" >/dev/null
  git add README.md
  git commit -m "docs: archive repository — development moved to ics-ot-protector monorepo"
  git push origin main
  popd >/dev/null
}

archive_repo() {
  local repo="$1"
  echo "==> Archiving ${ORG}/${repo}..."
  gh api -X PATCH "repos/${ORG}/${repo}" -f archived=true
}

rename_monorepo() {
  if $SKIP_RENAME; then
    echo "==> Skipping monorepo rename (--skip-rename)"
    return
  fi
  echo ""
  echo "==> Renaming ${MONOREPO} to ${NEW_NAME}..."
  gh repo rename "$NEW_NAME" --repo "$MONOREPO" -y
  echo "    New URL: ${MONOREPO_URL}"
  echo "    GitHub will redirect water-utility-protector URLs automatically."
}

for entry in "${LEGACY_REPOS[@]}"; do
  repo="${entry%%:*}"
  notice="${entry##*:}"
  push_archive_readme "$repo" "$notice"
  archive_repo "$repo"
done

rename_monorepo

echo ""
echo "Done. Legacy repos archived with pointers to ${MONOREPO_URL}"
echo ""
echo "Next steps:"
echo "  1. Verify archive banners appear on each legacy repo"
echo "  2. Update local git remotes: git remote set-url origin ${MONOREPO_URL}.git"
echo "  3. Update any external links to the old repo names"
