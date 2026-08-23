# GitHub credibility setup (Lane B)

Run this **once while logged into GitHub as `spinfosecurity`** (not the Cursor bot). It automates the hiring-visibility tasks that require account owner permissions.

## Quick start

```bash
gh auth login
cd ics-ot-protector
./scripts/setup-github-credibility.sh
```

## What it does

| Step | Action |
|------|--------|
| 1 | Sets **repo topics** on `ics-ot-protector` (OT/ICS, PowerShell, Bash, CISA, etc.) |
| 2 | **Closes stale PR #9** (superseded by main) |
| 3 | Checks pin status and prints **manual pin steps** (GitHub has no pin API) |
| 4 | **Publishes** `portfolio-site/` to `spinfosecurity.github.io` |
| 5 | Updates **`spinfosecurity/spinfosecurity`** profile README |

## Verify

- Topics: https://github.com/spinfosecurity/ics-ot-protector  
- Pinned repo: https://github.com/spinfosecurity  
- Live site: https://spinfosecurity.github.io  
- Profile README: https://github.com/spinfosecurity/spinfosecurity  

## Optional: automatic future deploys

After the one-shot script, add **`PAGES_DEPLOY_TOKEN`** on `ics-ot-protector` so the **Deploy portfolio site** workflow can push when `portfolio-site/` changes:

1. Fine-grained PAT → Contents read/write on `spinfosecurity.github.io` only  
2. Repo secret: `PAGES_DEPLOY_TOKEN` on `ics-ot-protector`  
3. Trigger: `gh workflow run deploy-portfolio-site.yml -R spinfosecurity/ics-ot-protector`

## Troubleshooting

**“Log in as spinfosecurity, not the Cursor bot”** — run `gh auth login` in your terminal, not in Cloud Agent.

**Pin step is manual** — GitHub does not provide an API to pin repos. Use Customize your pins on https://github.com/spinfosecurity.

**Profile repo missing** — the script creates `spinfosecurity/spinfosecurity` if needed. Enable it under GitHub → Settings → Profile → README.

**Pages push denied** — confirm you own `spinfosecurity.github.io` and `gh auth status` shows the correct account.

**Re-run after a partial success** — topics and PR close are idempotent. Run the script again to finish portfolio publish and profile README.
