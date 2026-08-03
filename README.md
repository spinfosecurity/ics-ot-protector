# Water Utility Protector (WUP WUP)

**WUP WUP** is an open-source cybersecurity scanner for water and wastewater utilities, designed to detect internet-exposed operational technology (OT) assets and remote access vulnerabilities. Built with PowerShell and Bash, it implements CISA Alert AA26-097A guidance and real-world threat intelligence from July 2026 water sector attacks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)

## What This Tool Does

- Scans OT subnets for exposed PLCs, HMIs, and remote access points
- Detects primary attack vectors: RDP (3389), VNC (5900), SSH (22)
- Identifies OT protocol exposure: EtherNet/IP (44818, 2222), Modbus (502), S7 (102)
- Prioritizes findings by severity (CRITICAL vs HIGH)
- Provides CISA-aligned remediation guidance
- Generates simple text reports for sharing with IT teams

## Real-World Threat Intelligence

This tool is built on actual attack patterns from:

- CISA Alert AA26-097A (July 2026) - Water sector PLC targeting
- FBI PSA 2026-08-01 - Iran-linked groups exploiting VNC
- CISA/EPA Joint Advisory - Internet-exposed HMIs
- July 2026 Water Sector Attacks - 30+ Minnesota utilities hit

## Key Features

### Threat Detection
- RDP (3389): PRIMARY ATTACK VECTOR - 70% of water sector breaches
- VNC (5900): Active exploitation by Iran-linked groups
- SSH (22): CISA-flagged in July 2026 water attacks
- EtherNet/IP (44818): Rockwell MicroLogix 1400 targeted (4,148 exposed globally)
- Modbus (502): Unauthenticated protocol (CVSS 9.3)

### Vendor-Specific Intelligence
- Rockwell: 4,148 exposed hosts (71% US) - MicroLogix 1400, CompactLogix
- Siemens: 4,117 exposed hosts (S7-1200) - 86% Europe
- Schneider: 2,072 exposed hosts (vendor-wide)

## Quick Start

### PowerShell Version (Windows)
```powershell
.\WUP-WUP.ps1
```

### Bash Version (Linux/macOS)
```bash
chmod +x wup_wup.sh
./wup_wup.sh
```

## What This Does NOT Do

- Does NOT test credentials or attempt authentication
- Does NOT modify system configurations
- Does NOT scan IT networks (OT/SCADA focus only)
- Does NOT replace professional penetration testing
- Does NOT detect active malware or intrusions
- Does NOT work over IPv6 (IPv4 only)
- Does NOT scan non-/24 subnets

## Documentation

- [PowerShell Guide](scripts/powershell/README.md) - Windows implementation
- [Bash Guide](scripts/bash/README.md) - Linux/macOS implementation
- [CISA Reference](docs/CISA-Reference.md) - Official guidance
- [Threat Intelligence](docs/Threat-Intelligence.md) - Attack patterns

## Technical Specifications

### Supported Platforms
- Windows: PowerShell 5.1+, .NET Framework 4.7+
- Linux: Bash 4.0+, standard utilities
- macOS: Bash 4.0+, standard utilities

### Limitations
- TCP port scan only (no UDP, no banner grabbing)
- Single-threaded (~2-5 minutes per subnet)
- May produce false negatives behind aggressive firewalls
- Requires local network access

## Sample Output

```
[!!! CRITICAL !!!] 192.168.10.78:5900 - VNC (Virtual Network Computing)
    Active exploitation by Iran-linked groups (FBI PSA 2026-08-01)
    Action: BLOCK IMMEDIATELY or restrict to VPN only
```

## Author

**Shannon P.** - Cybersecurity Consultant & IT Professional

- Associate\'s degree in Cybersecurity from Southern New Hampshire University (SNHU)
- Experience: Windows systems administration, PowerShell automation, OT security
- Focus: Water utility cybersecurity, ICS/SCADA protection, CISA compliance

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Issues & Support

- Bug Reports / Feature Requests: [Open an issue](https://github.com/spinfosecurity/water-utility-protector/issues)

## References

- [CISA Alert AA26-097A](https://www.cisa.gov/news-events/alerts/2026/07/30/cisa-urges-water-and-wastewater-systems-sector-protect-operational)
- [FBI IC3](https://www.ic3.gov)
- [EPA Water Sector Cybersecurity](https://www.epa.gov/watercybersecurity)
- [CISA Cyber Hygiene Services](https://www.cisa.gov/cyber-hygiene-services)

## Disclaimer

This tool is for defensive security assessment by authorized personnel only. Only scan networks you own or have explicit written permission to test.

---

**WUP WUP** - Emergency response for water utility security.

Made by [spinfosecurity](https://github.com/spinfosecurity)
