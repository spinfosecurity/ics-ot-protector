# Threat Model

Shared baseline for all ICS OT Protector sector scanners.

## Objective

From an authorized scan host, identify reachable remote-access services and industrial protocol ports that may indicate OT exposure candidates relevant to the selected sector scanner.

## In Scope

- TCP reachability checks against configured port catalogs
- Exposure-candidate detection with CRITICAL / HIGH / MEDIUM severity labels
- Local **JSON report export** (`schema_version` 1.0) with sector metadata and normalized findings

## Out of Scope

Exploitation, credential testing, authentication bypass, command execution, proof of device identity or vulnerability, compliance certification, and attribution.

## Limitations

Firewalls, routing, NAT, and host controls can create false positives or negatives. OT connection attempts can be operationally sensitive. A finding only means the scan host reached the recorded address and port at scan time — validate owner, device, controls, and vulnerability status before action.

## Sector Addenda

Sector-specific objectives and port coverage:

- [Water & Wastewater](sectors/water/threat-model.md)
- [Power Grid & Substation](sectors/energy-grid/threat-model.md)
- [Building Automation (BAS)](sectors/bas/threat-model.md)
- [Rail & Transit](sectors/rail/threat-model.md)
