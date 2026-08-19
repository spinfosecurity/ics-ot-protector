# Threat Model — Rail & Transit

> Shared baseline: [ICS OT Protector threat model](../../threat-model.md)

## Sector Objective

Identify EOT/HOT remote-linking exposure (CVE-2025-1727), RailSafe legacy SCADA API ports, standard ICS protocols, and remote-access services on authorized CIDR ranges.

## Sector-Specific Considerations

- Supports arbitrary CIDR (/8–/32) with configurable thread pool — use the narrowest approved subnet.
- `--eot_hot_only` / `-EotHotOnly` fast mode limits checks to EOT/HOT-related ports.
- CLI-driven scanner writes `ROP-results-*.json` to the configured output directory.
