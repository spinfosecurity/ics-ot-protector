# Energy Grid Protector (EGP)

Sector-specific OT/SCADA scanner for **power grid, transmission, and substation networks**. Part of the [ICS OT Protector monorepo](../../README.md).

## Quick Start

```bash
./scripts/ics-ot-protector.sh energy-grid -s 192.168.10.0/24
```

```powershell
.\scripts\ics-ot-protector.ps1 -Sector energy-grid -Subnet 192.168.10.0/24
```

Or run directly:

### PowerShell
```powershell
.\scanners\energy-grid\powershell\EGP.ps1 -Subnet 192.168.10.0/24
```

Fast CVE-only mode:
```powershell
.\scanners\energy-grid\powershell\EGP.ps1 -Subnet 192.168.10.0/24 -CveOnly
```

### Bash
```bash
./scanners/energy-grid/bash/EGP.sh 192.168.10.0/24
```

## Port Coverage

| Category | Ports | Notes |
|----------|-------|-------|
| Remote Access | 3389, 5900, 22, 23, 21, 80, 443 | RDP, VNC, SSH, Telnet, FTP, HTTP/S |
| ICS Protocols | 502, 20000, 2404, 102, 44818 | Modbus, DNP3, IEC 60870-5-104, S7, EtherNet/IP |
| Vendor CVEs | Hitachi Energy RTU500, ABB/B&R | Named CVE port checks |

## Documentation

- [Threat Model](../../docs/sectors/energy-grid/threat-model.md)
- [Sample Report](../../docs/sectors/energy-grid/sample-report.md)
- [Safe Operation](../../docs/sectors/energy-grid/safe-operation.md)

## Version

Current: **1.0.0** — CLI-driven, JSON reports (`EGP-results-*.json`), CVE fast-scan mode
