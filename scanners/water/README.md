# Water Utility Protector (WUP WUP)

Sector-specific OT/SCADA scanner for **water and wastewater utilities**. Detects internet-exposed PLCs, HMIs, and remote access aligned with CISA Alert AA26-097A.

## Quick Start

### PowerShell (Windows / cross-platform)
```powershell
.\scanners\water\powershell\WUP-WUP.ps1
```

Legacy path (backward compatible):
```powershell
.\scripts\powershell\WUP-WUP.ps1
```

### Bash (Linux / macOS)
```bash
./scanners/water/bash/WUP-WUP.sh
```

Legacy path (backward compatible):
```bash
./scripts/bash/WUP-WUP.sh
```

## Port Coverage

| Category | Ports | Protocols |
|----------|-------|-----------|
| Remote Access | 3389, 5900, 5901, 22, 80, 443, 8080, 8443 | RDP, VNC, SSH, Web HMI |
| OT Protocols | 44818, 2222, 502, 102, 20000, 47808, 20256 | EtherNet/IP, Modbus, S7, DNP3, BACnet, UniLogic |

## Documentation

- [CISA Reference](../../docs/sectors/water/CISA-Reference.md)
- [Threat Intelligence](../../docs/sectors/water/Threat-Intelligence.md)
- [Threat Model](../../docs/sectors/water/threat-model.md)
- [Sample Report](../../docs/sectors/water/sample-report.md)
- [PowerShell Guide](README-ps.md)
- [Bash Guide](README-bash.md)

## Version

Current: **3.4.0** (most mature scanner in the portfolio — interactive wizard, parallel scanning, behavioral test suite)
