# Publishing the portfolio site

The live site is [spinfosecurity.github.io](https://spinfosecurity.github.io). Source lives in `portfolio-site/` in this repo.

## One-time setup (already done for spinfosecurity)

Topics, site publish, and profile README were set up with:

```bash
gh auth login
./scripts/setup-github-credibility.sh
```

Log in as the account that owns the repos, not a bot token.

## When you change the site

**Option A — sync script:**

```bash
git clone https://github.com/spinfosecurity/spinfosecurity.github.io.git
./scripts/sync-portfolio-site.sh ../spinfosecurity.github.io
cd ../spinfosecurity.github.io
git add -A && git commit -m "Update portfolio" && git push
```

**Option B — GitHub Action:** add a `PAGES_DEPLOY_TOKEN` secret (fine-grained PAT with write access to `spinfosecurity.github.io`), then run the **Deploy portfolio site** workflow.

## Profile README

Template: `portfolio-site/GITHUB-PROFILE-README.md`  
Target repo: `spinfosecurity/spinfosecurity` (shown on your GitHub profile)

Update profile README only:

```bash
./scripts/setup-github-credibility.sh --profile-only
```

## Pinning a repo

GitHub still has no API for pinned repos. If needed: profile → **Customize your pins** → select `ics-ot-protector`.

## If something fails mid-run

Topics and PR cleanup are safe to re-run. If portfolio publish worked but profile README didn't:

```bash
git pull
./scripts/setup-github-credibility.sh --profile-only
```
