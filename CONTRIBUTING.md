# Contributing to ICS OT Protector

Thank you for your interest in contributing to the ICS OT Protector scanner portfolio!

## How to Contribute

### Reporting Bugs
Open an issue with steps to reproduce, expected vs actual behavior, sector scanner affected, and environment details.

### Pull Requests
1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Make your changes and test on your target platform
4. Run the test suite (see `tests/README.md`)
5. Commit with clear messages
6. Push and open a Pull Request

### Code Standards

PowerShell: Use approved verbs, comment-based help, parameter validation.
Bash: Use ShellCheck, follow Google Shell Style Guide, use `set -euo pipefail`.

When changing scanner logic, update the corresponding sector under `scanners/<sector>/` and its tests under `tests/<sector>/`.

## Development Setup

```bash
git clone https://github.com/spinfosecurity/water-utility-protector.git
cd water-utility-protector

# Run tests
bash tests/shared/bash/repository_tests.sh
pwsh -Command "Invoke-Pester (Get-ChildItem -Path ./tests -Recurse -Filter *.Tests.ps1) -CI"

# Run a sector scanner (example: water)
./scanners/water/bash/WUP-WUP.sh
```

## Sector Scanners

| Sector | Directory | Primary Contact Docs |
|--------|-----------|---------------------|
| Water | `scanners/water/` | `docs/sectors/water/` |
| Energy Grid | `scanners/energy-grid/` | `docs/sectors/energy-grid/` |
| BAS | `scanners/bas/` | `docs/sectors/bas/` |
| Rail | `scanners/rail/` | `docs/sectors/rail/` |
