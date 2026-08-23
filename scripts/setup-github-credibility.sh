#!/usr/bin/env bash
# One-shot GitHub credibility setup for job search (Lane B).
# Run locally as the spinfosecurity account: gh auth login && ./scripts/setup-github-credibility.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OWNER="${GITHUB_OWNER:-spinfosecurity}"
REPO="${GITHUB_REPO:-ics-ot-protector}"
PAGES_REPO="${GITHUB_PAGES_REPO:-spinfosecurity.github.io}"
PROFILE_REPO="${GITHUB_PROFILE_REPO:-spinfosecurity}"
PR_TO_CLOSE="${STALE_PR_NUMBER:-9}"

require_gh() {
  command -v gh >/dev/null 2>&1 || { echo "Install GitHub CLI: https://cli.github.com/" >&2; exit 1; }
  gh auth status >/dev/null 2>&1 || { echo "Run: gh auth login" >&2; exit 1; }
  local user
  user="$(gh api user -q .login 2>/dev/null || true)"
  if [[ "$user" == "cursor[bot]" ]] || [[ "$user" == "" ]]; then
    echo "Log in as ${OWNER}, not the Cursor bot. Run: gh auth login" >&2
    exit 1
  fi
  echo "Authenticated as: $user"
}

set_repo_topics() {
  local topics=(
    ics ics-security ot-security scada critical-infrastructure security-automation
    powershell bash modbus bacnet dnp3 cisa cybersecurity vulnerability-scanner
    network-security ot utility water
  )
  echo "Setting topics on ${OWNER}/${REPO}..."
  gh api -X PUT "repos/${OWNER}/${REPO}/topics" \
    -H "Accept: application/vnd.github+json" \
    --input <(printf '%s\n' "${topics[@]}" | jq -R . | jq -s '{names: .}')
  gh api "repos/${OWNER}/${REPO}/topics" -q '.names | join(", ")'
}

close_stale_pr() {
  local state
  state="$(gh pr view "$PR_TO_CLOSE" -R "${OWNER}/${REPO}" --json state -q .state 2>/dev/null || echo "MISSING")"
  if [[ "$state" == "OPEN" ]]; then
    echo "Closing stale PR #${PR_TO_CLOSE}..."
    gh pr close "$PR_TO_CLOSE" -R "${OWNER}/${REPO}" \
      -c "Superseded by portfolio-site/ and hiring pack on main (PRs #13, #15)."
  else
    echo "PR #${PR_TO_CLOSE} already ${state}; skipping."
  fi
}

pin_flagship_repo() {
  echo "Pinning ${OWNER}/${REPO} on GitHub profile..."
  local owner_id repo_id
  owner_id="$(gh api graphql -f query='query($l:String!){user(login:$l){id}}' -f l="$OWNER" -q .data.user.id)"
  repo_id="$(gh api graphql -f query='query($o:String!,$n:String!){repository(owner:$o,name:$n){id}}' -f o="$OWNER" -f n="$REPO" -q .data.repository.id)"
  gh api graphql -f query='mutation($owner:ID!,$repo:ID!){
    replacePinnedItems(input:{ownerId:$owner,pinnedItems:[{id:$repo,type:REPOSITORY}]}) {
      pinnedItems { ... on Repository { nameWithOwner } }
    }
  }' -f owner="$owner_id" -f repo="$repo_id" -q '.data.replacePinnedItems.pinnedItems[].nameWithOwner'
}

deploy_portfolio_site() {
  local tmp pages_dir="${ROOT}/portfolio-site"
  [[ -d "$pages_dir" ]] || { echo "Missing $pages_dir" >&2; exit 1; }
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  echo "Cloning ${OWNER}/${PAGES_REPO}..."
  gh repo clone "${OWNER}/${PAGES_REPO}" "$tmp/pages" -- --depth=1
  "${ROOT}/scripts/sync-portfolio-site.sh" "$tmp/pages"
  cd "$tmp/pages"
  if git diff --quiet && git diff --cached --quiet; then
    echo "Portfolio site already up to date."
    return 0
  fi
  git add -A
  git commit -m "Update portfolio site (hiring pack + SEO)"
  git push origin main
  echo "Published: https://${OWNER}.github.io/"
}

update_profile_readme() {
  local tmp src="${ROOT}/portfolio-site/GITHUB-PROFILE-README.md"
  [[ -f "$src" ]] || { echo "Missing $src" >&2; return 1; }
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  if gh repo view "${OWNER}/${PROFILE_REPO}" >/dev/null 2>&1; then
    gh repo clone "${OWNER}/${PROFILE_REPO}" "$tmp/profile" -- --depth=1
  else
    echo "Creating ${OWNER}/${PROFILE_REPO} for profile README..."
    gh repo create "${OWNER}/${PROFILE_REPO}" --public --description "GitHub profile README" --clone=false
    gh repo clone "${OWNER}/${PROFILE_REPO}" "$tmp/profile" -- --depth=1
  fi
  head -n 33 "$src" > "$tmp/profile/README.md"
  cd "$tmp/profile"
  git add README.md
  if git diff --cached --quiet; then
    echo "Profile README unchanged."
    return 0
  fi
  git commit -m "Update profile README for hiring visibility"
  git push origin main
  echo "Profile README updated: https://github.com/${OWNER}"
}

print_deploy_token_instructions() {
  cat <<EOF

Optional — enable automatic portfolio deploys from ics-ot-protector:
  1. Create a fine-grained PAT with Contents read/write on ${PAGES_REPO}
  2. Add repo secret PAGES_DEPLOY_TOKEN on ${OWNER}/${REPO}
  3. Run: gh workflow run deploy-portfolio-site.yml -R ${OWNER}/${REPO}

EOF
}

main() {
  require_gh
  set_repo_topics
  close_stale_pr
  pin_flagship_repo
  deploy_portfolio_site
  update_profile_readme
  print_deploy_token_instructions
  echo "Lane B complete."
}

main "$@"
