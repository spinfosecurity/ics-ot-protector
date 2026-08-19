# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/) and intends to use [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
