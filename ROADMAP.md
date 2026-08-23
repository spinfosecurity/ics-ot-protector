# Roadmap

This roadmap describes intended defensive improvements. It is not a commitment or release schedule.

**Current state:** [PROJECT_STATUS.md](docs/PROJECT_STATUS.md) · **Latest release:** v4.4.0

## v4.2.x — Shared engine & operator safety ✅
- Shared Bash/PowerShell scan engine and non-interactive scan mode
- Pre-flight scope validation with `--force` for large subnets
- `metadata.summary` and optional CSV export in scan mode
- Fixture-based engine and export integration tests

## v4.3.x — Configurability ✅
- `--config` / YAML overlay merged at runtime onto sector JSON
- Shared scan progress + ETA in scan mode and interactive WUP/BAS
- Interactive WUP/BAS parity: preflight, `metadata.summary`, CSV export

## v4.4.x — Workflow integration ✅
- Structured remediation metadata and extended report summaries
- Offline report-review workflow and CLI helpers
- SIEM/ticketing ingestion examples — **deferred**

## Portfolio & hiring presence ✅
- Live site at [spinfosecurity.github.io](https://spinfosecurity.github.io)
- Employer guide, credibility setup script, portfolio deploy workflow
- See [for-employers.md](docs/for-employers.md) and [github-credibility-setup.md](docs/github-credibility-setup.md)

## Future (if development resumes)
- Safe fixture-driven tests for sector-specific detection hooks
- Community-contributed detection improvements, subject to defensive-use review
- IPv6 scope support (currently IPv4 only)
- SIEM/ticketing ingestion examples
