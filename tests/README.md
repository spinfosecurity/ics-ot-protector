# Test Suite

These tests validate repository integrity and scanner logic without interacting with a network or an OT asset. They are part of the [ICS OT Protector](../../README.md) monorepo — see the root README **Engineering highlights** section for the full quality story.

## Layout

```
tests/
├── shared/          # Monorepo-wide validation (all sectors present, all scripts parse)
├── water/           # WUP WUP behavioral + repository tests
├── energy-grid/     # EGP repository tests
├── bas/             # BAS Guardian repository tests
└── rail/            # ROP repository tests
```

## Running Tests

### PowerShell (Pester)
```powershell
Invoke-Pester ./tests/shared/PowerShell ./tests/water/PowerShell ./tests/energy-grid/PowerShell ./tests/bas/PowerShell ./tests/rail/PowerShell -CI
```

### Bash
```bash
bash tests/shared/bash/repository_tests.sh
bash tests/water/bash/repository_tests.sh
bash tests/water/bash/behavioral_tests.sh
bash tests/energy-grid/bash/repository_tests.sh
bash tests/bas/bash/repository_tests.sh
bash tests/rail/bash/repository_tests.sh
```

## Safety

The test suite does **not** execute live network scans. It performs no port checks, HTTP requests, authentication attempts, device commands, or other network activity. Behavioral tests source scanner functions in test mode or use mock listeners on localhost where needed.
