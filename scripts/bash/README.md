# Bash Version

Full feature-parity implementation of WUP WUP for Linux and macOS.

## Usage

```bash
chmod +x scripts/bash/WUP-WUP.sh
./scripts/bash/WUP-WUP.sh
```

## Requirements

- Bash 4.0+
- `bc` (arbitrary-precision calculator — for scan time estimates)
- `timeout` (GNU coreutils — for TCP connection timeout)
- Standard POSIX utilities (`date`, `awk`, `grep`, `seq`)

On **macOS**, `timeout` and a newer Bash may not be installed by default:

```bash
brew install coreutils bash
```

Then invoke with the updated Bash path, or add it to your `PATH`.

## Features

- Identical port coverage, threat intelligence, and severity prioritization to the PowerShell version
- Color-coded console output (ANSI escape codes)
- Per-subnet progress bars
- Optional text report export to `~/WaterUtilitySecurity/Reports/`
- Parallel per-host scanning (up to 50 concurrent background workers)
- Clean-scan report generated even when no findings are detected
- No external dependencies beyond standard shell utilities listed above

See the root [README.md](../../README.md) for full documentation.
