# Roadmap

This roadmap describes intended defensive improvements. It is not a commitment or release schedule.

## v4.2.x — Shared engine & operator safety (current)
- ✅ Shared Bash/PowerShell scan engine and non-interactive scan mode
- ✅ Pre-flight scope validation with `--force` for large subnets
- ✅ `metadata.summary` and optional CSV export in scan mode
- ✅ Fixture-based engine and export integration tests

## v4.3 — Configurability
- Configurable approved port profiles and scan settings (`--config` / custom YAML overlays)
- Wire pre-flight, summary, and CSV into interactive sector scanners
- Clearer operator feedback during long scans (progress, ETA)

## v4.4 — Workflow integration
- Example mappings for SIEM, ticketing, and ITSM ingestion
- More structured remediation metadata and report summaries
- Offline report-review workflow examples

## Future
- Safe fixture-driven tests for sector-specific detection hooks
- Community-contributed detection improvements, subject to defensive-use review
- IPv6 scope support (currently IPv4 only)
