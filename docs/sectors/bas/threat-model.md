# Threat Model — Building Automation (BAS)

> Shared baseline: [ICS OT Protector threat model](../../threat-model.md)

## Sector Objective

Identify exposed BACnet/IP, BACnet/SC, LonWorks, and remote-access services on BMS/HVAC workstations, plus vendor-specific BMS platform exposure candidates.

## Sector-Specific Considerations

- Vendor alert checks cover Honeywell, Johnson Controls, Siemens, and Tridium port indicators from compiled config.
- BACnet Who-Is/I-Am broadcast abuse (CVE-2026-24060) is documented in threat context but not actively triggered by this scanner.
- Interactive wizard with optional JSON export to `./reports/BAS-results-*.json`.
