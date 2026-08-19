# Energy Grid Protector (EGP)

Sector-specific OT/SCADA scanner for **power grid, transmission, and substation networks**. Detects ICS protocol exposure, vendor CVEs (Hitachi Energy, ABB, B&R), and remote-access risks aligned with NERC CIP and CISA ICS advisories.

## Quick Start

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

Current: **1.0.0** (CLI-driven, parameterized subnet input)
