# Project status

**Last updated:** 2026-08-23  
**Current release:** [v4.4.0](releases/v4.4.0.md)  
**Portfolio:** [spinfosecurity.github.io](https://spinfosecurity.github.io)

This document is a handoff summary for anyone picking up the project later.

---

## What shipped (v4.2 → v4.4)

| Version | Focus |
|---------|--------|
| **v4.2.0** | Shared Bash/PowerShell scan engine, preflight, `metadata.summary`, CSV export, integration tests |
| **v4.3.0** | `--config` YAML overlays, scan progress/ETA, interactive WUP/BAS parity |
| **v4.4.0** | Remediation metadata, extended summaries, offline report-review CLI |

---

## Hiring & public presence (complete)

| Asset | Location |
|-------|----------|
| Portfolio site (live) | https://spinfosecurity.github.io |
| Site source mirror | `portfolio-site/` in this repo |
| Employer review guide | [for-employers.md](for-employers.md) |
| GitHub setup script | `scripts/setup-github-credibility.sh` |
| Resume bullet helper | `scripts/resume-bullets-from-report.sh` |
| Org profile README template | `portfolio-site/GITHUB-PROFILE-README.md` |

**Deploy portfolio changes:**

```bash
./scripts/sync-portfolio-site.sh /path/to/spinfosecurity.github.io
# or add PAGES_DEPLOY_TOKEN and run the Deploy portfolio site workflow
```

---

## Deferred (not started)

- SIEM/ticketing ingestion examples
- IPv6 scope support
- Sector-specific fixture tests beyond water behavioral suite
- SundayStack / other repos (out of scope for this monorepo)

---

## Quick verification

```bash
bash tests/shared/bash/remediation_review_tests.sh
bash tests/shared/bash/scan_engine_integration_tests.sh
./scripts/review_scan_report.sh docs/sample-report.json
```

PowerShell (requires `pwsh`):

```powershell
Invoke-Pester (Get-ChildItem ./tests -Recurse -Filter *.Tests.ps1) -CI
```

---

## Maintenance notes

- Sector configs: edit `config/sectors/*.yaml`, run `bash tests/shared/bash/validate_configs.sh`, commit JSON if changed
- CI: `.github/workflows/ci.yml` on every push/PR
- Cloud Agent bootstrap: `.cursor/install.sh` + `.cursor/environment.json`
