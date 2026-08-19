# Rail-OT-Protector (ROP)

Sector-specific scanner for **rail and transit OT/SCADA networks**. Detects CVE-2025-1727 (EOT/HOT weak authentication), RailSafe legacy API exposure, and standard ICS/remote-access risks.

## Quick Start

### PowerShell
```powershell
pwsh ./scanners/rail/powershell/ROP.ps1 -Subnets 10.10.20.0/24 -OutputDir ./reports
```

Fast EOT/HOT-only mode:
```powershell
pwsh ./scanners/rail/powershell/ROP.ps1 -Subnets 10.10.20.0/24 -EotHotOnly
```

### Bash
```bash
./scanners/rail/bash/ROP.sh 10.10.20.0/24
```

## Port Coverage

| Category | Ports | Notes |
|----------|-------|-------|
| Remote Access | 3389, 5900, 22, 23 | RDP, VNC, SSH, Telnet |
| ICS Protocols | 502, 20000, 44818, 2404, 102 | Modbus, DNP3, EtherNet/IP, IEC 60870-5-104, S7 |
| Rail-Specific | EOT/HOT, RailSafe API | CVE-2025-1727 indicators |

Reports are exported as **JSON** (`ROP-results-*.json`) with CRITICAL/HIGH/MEDIUM severity labels.

## Documentation

- [CISA Reference](../../docs/sectors/rail/CISA-Reference.md)
- [Threat Intelligence](../../docs/sectors/rail/Threat-Intelligence.md)
- [Threat Model](../../docs/sectors/rail/threat-model.md)
- [Sample Report](../../docs/sectors/rail/sample-report.md)
- [Safe Operation](../../docs/sectors/rail/safe-operation.md)

## Version

Current: **1.0.0** (CLI-driven, multi-subnet, JSON report output)
