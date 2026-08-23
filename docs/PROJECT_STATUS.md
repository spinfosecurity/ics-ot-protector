# Project status

Last updated: 2026-08-23  
Release: [v4.4.1](releases/v4.4.1.md)  
Site: [spinfosecurity.github.io](https://spinfosecurity.github.io)

Notes for picking this back up later.

## Recent releases

- **v4.4.x** — remediation metadata on findings, offline report review CLI, hiring/portfolio docs
- **v4.3.x** — `--config` overlays, scan progress, WUP/BAS parity with scan mode
- **v4.2.x** — shared scan engine, preflight, JSON summary + CSV export

## Public-facing stuff

Portfolio source is in `portfolio-site/`. Employer-facing write-up: [for-employers.md](for-employers.md). Publish changes with `scripts/sync-portfolio-site.sh` or the deploy workflow (see [github-credibility-setup.md](github-credibility-setup.md)).

## Not planned yet

SIEM/ticketing examples, IPv6 scanning, deeper fixture tests for EGP/BAS/rail.

## Smoke test

```bash
bash tests/shared/bash/remediation_review_tests.sh
./scripts/review_scan_report.sh docs/sample-report.json
```

With PowerShell installed:

```powershell
Invoke-Pester (Get-ChildItem ./tests -Recurse -Filter *.Tests.ps1) -CI
```

## Day-to-day maintenance

Edit sector YAML in `config/sectors/`, run `bash tests/shared/bash/validate_configs.sh`, commit JSON if it changed. CI is in `.github/workflows/ci.yml`. Cloud Agent bootstrap: `.cursor/install.sh`.
