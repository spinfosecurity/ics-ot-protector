# Tests

These tests validate repository integrity without interacting with a network or an OT asset.

- `PowerShell/Repository.Tests.ps1` parses PowerShell source and validates required project documentation.
- `bash/repository_tests.sh` runs Bash syntax checks and validates required project documentation.

The test suite does **not** dot-source or execute scanner scripts. It performs no port checks, HTTP requests, authentication attempts, device commands, or other network activity.

## Run locally

```powershell
Install-Module Pester -Scope CurrentUser
Invoke-Pester ./tests/PowerShell -Output Detailed
```

```bash
bash ./tests/bash/repository_tests.sh
```
