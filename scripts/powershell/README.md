# PowerShell Version

Full implementation of WUP WUP for Windows (and PowerShell Core on Linux/macOS).

## Usage

```powershell
.\scripts\powershell\WUP-WUP.ps1
```

If execution policy blocks the script, run in the same shell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Requirements

- Windows PowerShell 5.1+ **or** PowerShell Core 7+ (cross-platform)
- .NET Framework 4.7+ (Windows) or .NET 6+ (PowerShell Core)

## Features

- Interactive multi-step wizard (subnet selection, timeout, report export)
- Color-coded console output with CRITICAL / HIGH severity tagging
- Per-subnet progress bars and real-time scan rate display
- Optional text report export to `~/WaterUtilitySecurity/Reports/`
- Parallel per-host scanning via runspace pool (up to 50 concurrent runspaces)
- Cross-platform report path (works on Windows, Linux, macOS)
- Clean-scan report generated even when no findings are detected

See the root [README.md](../../README.md) for full documentation.
