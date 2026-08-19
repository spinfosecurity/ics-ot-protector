# Sector Scanner Configuration

Sector-specific port tables, threat intelligence, and CVE definitions live here as **YAML** (human-editable source) and **JSON** (runtime format for scanners). CI recompiles YAML and fails on drift — part of the shared config pipeline in the [ICS OT Protector](../../README.md) monorepo.

## Layout

```
config/sectors/
├── water.yaml / water.json
├── energy-grid.yaml / energy-grid.json
├── bas.yaml / bas.json
└── rail.yaml / rail.json
```

## Editing

1. Edit the `.yaml` file for the sector you are changing.
2. Recompile JSON:
   ```bash
   pip install pyyaml   # once
   python3 scripts/config/compile_configs.py
   ```
3. Run validation:
   ```bash
   bash tests/shared/bash/validate_configs.sh
   bash tests/shared/bash/config_behavioral_tests.sh
   ```

Scanners load the compiled `.json` files via `scanners/_shared/Import-SectorConfig.ps1` (PowerShell) and `scanners/_shared/load_sector_config.sh` (Bash).

## Schema overview

| Sector | Key sections |
|--------|----------------|
| water | `remote_access_ports`, `ot_protocol_ports`, `threat_context` |
| energy-grid | `cve_checks`, `remote_access_ports`, `ics_ports` |
| bas | `bas_protocol_ports`, `remote_access_ports`, `threat_context`, `vendor_alerts` |
| rail | `port_catalog` (with `category`: EotHot, RailSafe, RemoteAccess, ICS) |
