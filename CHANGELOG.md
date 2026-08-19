# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/) and intends to use [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [3.4.0] - 2026-08-19

### Added
- **Parallel scanning** (PowerShell): per-host scanning now uses a runspace pool (up to 50 concurrent runspaces), dramatically reducing wall-clock time versus the previous sequential loop. Results are collected and displayed as each host completes.
- **Parallel scanning** (Bash): per-host scanning now dispatches background workers (up to 50 concurrent), with findings written to per-host temp files and collected in IP order after all workers complete.
- **Behavioral test suite** (Bash): `tests/bash/behavioral_tests.sh` — 62 tests covering `get_threat_context`, port table completeness, service token extraction, CRITICAL classification, report generation (with and without findings), and the `scan_host` worker function.
- **Behavioral test suite** (PowerShell): `tests/PowerShell/WupWup.Behavioral.Tests.ps1` — Pester tests for `ThreatContext` table, port table keys, `Get-NetworkPrefix`, service token extraction, `Show-ScanHeader`/`Show-ScanComplete` overflow safety, `Generate-Report` content and clean-scan behavior, and `ScriptInfo` metadata.
- **Clean-scan report** (both): when a user opts into report export but no findings are detected, a report is now generated anyway (documenting a clean scan result), rather than silently producing no file.
- **Source guard** (Bash): `WUP-WUP.sh` now uses `[[ "${BASH_SOURCE[0]}" == "${0}" ]]` to skip `main()` when sourced, enabling the behavioral test suite to load functions without triggering interactive execution.

### Fixed
- **`Ask-Subnets` loop counter bug** (PowerShell): invalid subnet entries (wrong format or non-/24 prefix length) were consuming one of the user's 5 allowed slots. The prompt number now reflects how many valid subnets have been accepted, and users can re-enter after a validation error without wasting a slot.
- **`Show-ScanHeader` box overflow** (PowerShell): box width was hard-coded at 50 characters; a long subnet string caused the right border to overflow. Width is now derived dynamically from the longest content line.

### Changed
- Script version bumped to `3.4.0` in both PowerShell and Bash implementations.

## [3.3.0] - 2026-08-19

### Added
- **Bash implementation** (`scripts/bash/WUP-WUP.sh`): full feature-parity port of the PowerShell scanner for Linux and macOS. Includes identical port coverage, threat context, color-coded output, progress display, and text report export.

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
