# BAS Guardian

Sector-specific scanner for **Building Automation Systems (BAS)**, BACnet devices, and HVAC/BMS controllers. Detects CVE-2026-3611 (CVSS 10.0), CVE-2026-24060, and exposed Tridium/Honeywell/Johnson Controls/Siemens systems.

## Quick Start

### PowerShell
```powershell
.\scanners\bas\powershell\BAS-Guardian.ps1
```

### Bash
```bash
./scanners/bas/bash/BAS-Guardian.sh
```

## Port Coverage

| Category | Ports | Notes |
|----------|-------|-------|
| BAS Protocols | 47808, 47809, 4800, 1628, 47800, 9998, 1911, 4911 | BACnet/IP, LonWorks, Tridium Niagara |
| Remote Access | 3389, 5900, 5901, 22, 80, 443, 8080, 8443 | RDP, VNC, SSH, Web BMS |
| Vendor CVEs | 5489, 5010, 2404, 1911 | Honeywell, Johnson Controls, Siemens, Tridium |

## Documentation

- [CISA Reference](../../docs/sectors/bas/CISA-Reference.md)
- [Threat Intelligence](../../docs/sectors/bas/Threat-Intelligence.md)
- [Threat Model](../../docs/sectors/bas/threat-model.md)
- [Sample Report](../../docs/sectors/bas/sample-report.md)
- [PowerShell Guide](README-ps.md)
- [Bash Guide](README-bash.md)

## Version

Current: **2.0.0** (interactive wizard with vendor-specific CVE intelligence)
