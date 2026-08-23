# Threat Model — Power Grid & Substation

> Shared baseline: [ICS OT Protector threat model](../../threat-model.md)

## Sector Objective

Identify named vendor CVE exposure candidates (Hitachi Energy, ABB, B&R), remote-access services, and grid ICS protocols (DNP3, Modbus, IEC 60870-5-104, IEC 61850, EtherNet/IP, PROFINET, OPC UA) on authorized /24 subnets.

## Sector-Specific Considerations

- CVE-only fast-scan mode checks configured vendor CVE port tables without full ICS/remote-access sweeps.
- Substation and transmission environments may have strict maintenance windows — coordinate with grid operations before scanning.
- CLI-driven scanner writes `EGP-results-*.json` to the configured output directory.
