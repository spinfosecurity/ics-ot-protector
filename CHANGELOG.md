# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/) and intends to use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Shared Bash scan engine** — `scanners/_shared/scan_engine.sh` with `run_tcp_port_scan()` for unified host×port probing, deduplication, and parallel workers
- **Full CIDR expansion** — `expand_cidr()` and `build_scan_targets()` in `scanner_helpers.sh`
- **Energy-grid port catalog builder** — `build_energy_grid_port_catalog()` converts sector config to unified port records

### Changed
- **EGP and ROP Bash scanners** — refactored to use the shared scan engine instead of inline scan loops
- **WUP WUP and BAS Guardian Bash scanners** — refactored to use the shared scan engine and port catalog builders
- **Unified launcher** — added non-interactive `scan` mode: `./scripts/ics-ot-protector.sh scan --sector <name> --subnets <CIDRs>`
- **Non-interactive scan runner** — `scanners/_shared/run_sector_scan.sh` for all sectors via the shared engine
- **Water and BAS port catalog builders** — `build_water_port_catalog()` and `build_bas_port_catalog()`

## [4.1.2] - 2026-08-23

### Added
- **EGP v1.1.0 port coverage** — PROFINET RT/RTA (34962, 34963) and OPC UA (4840) merged from standalone Energy-Grid-Protector into `config/sectors/energy-grid.yaml`

### Fixed
- **EGP — finding deduplication** — host:port reported once across CVE, remote-access, and ICS checks (parity with standalone v1.1.0)
- **EGP PowerShell — socket cleanup** — `Test-TcpPort` now disposes the `TcpClient` in a `finally` block (parity with standalone v1.1.0)

## [4.1.1] - 2026-08-19

### Added
- **Shared Bash TCP probe** — `test_tcp_port` in `scanner_helpers.sh`, used by all Bash scanners

### Changed
- EGP Bash JSON metadata now matches PowerShell (scan mode, target, timeout, reference)
- WUP/BAS subnet helpers deduplicated to shared modules (from PR #7)

## [4.1.0] - 2026-08-19

### Added
- **Unified JSON export** — shared `Export-ScanReport.ps1` and `export_scan_report.sh`; all scanners write `schema_version` 1.0 JSON reports
- **Unified sector launcher** — `scripts/ics-ot-protector.ps1` and `scripts/ics-ot-protector.sh`
- **Sample JSON report** — `docs/sample-report.json` with schema documentation
- **Export and launcher tests** — `tests/shared/PowerShell/Export.Tests.ps1`, `tests/shared/bash/launcher_tests.sh`
- **CI config drift guard** — fails when compiled `config/sectors/*.json` does not match YAML

### Changed
- EGP, BAS, ROP, and WUP scanners now export JSON only (CSV and text report files removed)
- Root and sector documentation split into shared baseline + sector addenda
- EGP and ROP PowerShell scanners deduplicated to shared `ScannerHelpers.ps1`

## [4.0.0] - 2026-08-19
- **Unified ICS OT Protector monorepo** — consolidated four sector-specific scanner projects into one repository:
  - `scanners/water/` — Water Utility Protector (WUP WUP) v3.4.0
  - `scanners/energy-grid/` — Energy Grid Protector (EGP) v1.0.0
  - `scanners/bas/` — BAS Guardian v2.0.0
  - `scanners/rail/` — Rail-OT-Protector (ROP) v1.0.0
- **Sector-specific documentation** under `docs/sectors/{water,energy-grid,bas,rail}/`
- **Monorepo test suite** — shared validation plus per-sector repository and behavioral tests
- **Shared sector YAML/JSON configuration** under `config/sectors/`
- **Backward-compatible launchers** for the water scanner at legacy `scripts/` paths
- **Sector READMEs** with quick-start commands and port coverage tables for each scanner

### Removed
- **Printer SNMP consumables tooling** — unrelated to ICS/OT scanning; removed from the repository

### Added
- **Repository migration tooling** — archive notice READMEs (`docs/archive-notices/`), admin script (`scripts/admin/archive-legacy-repos.sh`), and [migration guide](docs/repository-migration.md) for archiving legacy standalone repos and renaming to `ics-ot-protector`

### Changed
- **Canonical repository branding** updated to `spinfosecurity/ics-ot-protector` across README, SECURITY.md, CONTRIBUTING.md, and EGP scanner output

### Changed
- Repository restructured from single-scanner layout to multi-sector monorepo
- CI updated to lint and test all four sector scanners
- Root README rewritten as unified portfolio documentation

## [3.4.0] - 2026-08-19

### Added
- **Parallel scanning** (PowerShell): per-host scanning now uses a runspace pool (up to 50 concurrent runspaces), dramatically reducing wall-clock time versus the previous sequential loop. Results are collected and displayed as each host completes.
- **Parallel scanning** (Bash): per-host scanning now dispatches background workers (up to 50 concurrent), with findings written to per-host temp files and collected in IP order after all workers complete.
- **Behavioral test suite** (Bash): `tests/water/bash/behavioral_tests.sh` — 62 tests covering `get_threat_context`, port table completeness, service token extraction, CRITICAL classification, report generation (with and without findings), and the `scan_host` worker function.
- **Behavioral test suite** (PowerShell): `tests/water/PowerShell/WupWup.Behavioral.Tests.ps1` — Pester tests for `ThreatContext` table, port table keys, `Get-NetworkPrefix`, service token extraction, `Show-ScanHeader`/`Show-ScanComplete` overflow safety, `Generate-Report` content and clean-scan behavior, and `ScriptInfo` metadata.
- **Clean-scan report** (both): when a user opts into report export but no findings are detected, a report is now generated anyway (documenting a clean scan result), rather than silently producing no file.
- **Source guard** (Bash): `WUP-WUP.sh` now uses `[[ "${BASH_SOURCE[0]}" == "${0}" ]]` to skip `main()` when sourced, enabling the behavioral test suite to load functions without triggering interactive execution.

### Fixed
- **`Ask-Subnets` loop counter bug** (PowerShell): invalid subnet entries (wrong format or non-/24 prefix length) were consuming one of the user's 5 allowed slots. The prompt number now reflects how many valid subnets have been accepted, and users can re-enter after a validation error without wasting a slot.
- **`Show-ScanHeader` box overflow** (PowerShell): box width was hard-coded at 50 characters; a long subnet string caused the right border to overflow. Width is now derived dynamically from the longest content line.

### Changed
- Script version bumped to `3.4.0` in both PowerShell and Bash implementations.

## [3.3.0] - 2026-08-19

### Added
- **Bash implementation** (`scanners/water/bash/WUP-WUP.sh`): full feature-parity port of the PowerShell scanner for Linux and macOS. Includes identical port coverage, threat context, color-coded output, progress display, and text report export.

### Fixed
- **ThreatContext lookup for Web HMI ports** (PowerShell): HTTP/HTTPS service tokens were not matching `ThreatContext` keys; lookup now correctly maps `HTTP` and `HTTPS`.
- **ThreatContext for OT protocol findings** (PowerShell & Bash): OT protocol findings now display threat context in both console output and generated reports; `ThreatContext` field was missing from stored findings objects.
- **`Ask-Timeout` validation loop bug** (PowerShell): entering `0` caused the `do/while` loop to exit prematurely because `0` is falsy in PowerShell; loop now tests `$null -eq $timeout` explicitly.
- **`Show-ScanComplete` padding underflow** (PowerShell): box-drawing padding calculation could produce a negative repeat count for larger elapsed times or finding counts; clamped to zero with `[math]::Max`.
- **Estimated scan time** (PowerShell): confirmation screen now shows a realistic worst-case estimate derived from subnet count × hosts × timeout × port count, rather than a fixed 2.5 min/subnet constant.
- **Hardcoded Windows report path** (PowerShell): report directory changed from `C:\WaterUtilitySecurity\Reports` to `~/WaterUtilitySecurity/Reports` via `[System.Environment]::GetFolderPath('UserProfile')`, making the script work on PowerShell Core (Linux/macOS).
- **HIGH findings missing `ThreatContext` in report** (PowerShell): generated text reports now include the `Context:` field for HIGH-severity findings, matching the layout of CRITICAL findings.
- **Statistics box alignment** (PowerShell): scan statistics and findings summary boxes now use a helper function to ensure consistent padding regardless of value length.

### Changed
- **OT protocol findings now show `[!! HIGH !!]`** prefix in console (was `[!]`) for visual consistency with remote access HIGH findings.
- Script version bumped to `3.3.0`.

## [1.0.0] - 2026-08-16
- Initial public release for authorized water and wastewater OT/SCADA exposure assessment.
- PowerShell and Bash scanners with defensive reporting.
