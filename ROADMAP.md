# Roadmap

This roadmap describes intended defensive improvements. It is not a commitment or release schedule.

## v4.2.x — Shared engine & operator safety
- ✅ Shared Bash/PowerShell scan engine and non-interactive scan mode
- ✅ Pre-flight scope validation with `--force` for large subnets
- ✅ `metadata.summary` and optional CSV export in scan mode
- ✅ Fixture-based engine and export integration tests

## v4.3.x — Configurability
- ✅ `--config` / YAML overlay merged at runtime onto sector JSON
- ✅ Shared scan progress + ETA in scan mode and interactive WUP/BAS
- ✅ Interactive WUP/BAS parity: preflight, `metadata.summary`, CSV export

## v4.4.x — Workflow integration (current)
- ✅ Structured remediation metadata and extended report summaries
- ✅ Offline report-review workflow and CLI helpers
- ⏭️ SIEM/ticketing ingestion examples (deferred)

## Future
- Safe fixture-driven tests for sector-specific detection hooks
- Community-contributed detection improvements, subject to defensive-use review
- IPv6 scope support (currently IPv4 only)
