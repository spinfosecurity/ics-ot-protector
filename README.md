# Water Utility Protector (WUP WUP) - Free Water & Wastewater Cybersecurity Scanner

**WUP WUP (Water Utility Protector)** is a free, open-source cybersecurity scanning tool built to help water and wastewater utilities detect internet-exposed industrial control systems (ICS), SCADA devices, and remote access vulnerabilities before attackers exploit them. Available in both **PowerShell** and **Bash**, WUP WUP implements guidance from CISA Alert AA26-097A and real-world threat intelligence from the July 2026 water sector cyberattacks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![CISA AA26-097A](https://img.shields.io/badge/CISA-AA26--097A%20Response-red)](#)
[![EPA WaterISAC](https://img.shields.io/badge/EPA-Water%20Sector%20Cybersecurity-blue)](#)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)]()
[![GitHub issues](https://img.shields.io/github/issues/spinfosecurity/water-utility-protector)](https://github.com/spinfosecurity/water-utility-protector/issues)
[![GitHub stars](https://img.shields.io/github/stars/spinfosecurity/water-utility-protector?style=social)](https://github.com/spinfosecurity/water-utility-protector/stargazers)

---

## About

Water and wastewater utilities across the United States are facing an escalating wave of cyberattacks targeting exposed programmable logic controllers (PLCs), human-machine interfaces (HMIs), and remote access systems. In July 2026, coordinated attacks disrupted operations at more than 30 water utilities in Minnesota, and CISA Alert AA26-097A (July 30, 2026) confirmed active nation-state exploitation of internet-facing OT infrastructure nationwide.

**WUP WUP** was built to give water utility IT teams, OT engineers, and cybersecurity consultants a fast, free way to identify these exact exposures on their own networks — without needing expensive commercial scanning tools or deep penetration testing expertise.

**Keywords:** water utility cybersecurity, ICS security scanner, SCADA vulnerability scanner, OT network security tool, CISA AA26-097A compliance scanner, PowerShell security script, Bash security script, critical infrastructure protection, water treatment cyberattack detection, industrial control systems security, Modbus scanner, EtherNet/IP scanner, PLC security, HMI exposure detection

## What This Tool Does

- **Scans OT subnets** for exposed PLCs, HMIs, and remote access points
- **Detects primary attack vectors**: RDP (3389), VNC (5900), SSH (22)
- **Identifies OT protocol exposure**: EtherNet/IP (44818, 2222), Modbus (502), S7 (102), DNP3 (20000), BACnet/IP (47808)
- **Prioritizes findings by severity** (CRITICAL vs HIGH) based on real attack data
- **Provides CISA-aligned remediation guidance** for every finding
- **Generates simple text reports** for sharing with IT and OT teams
- **Runs on Windows, Linux, and macOS** via matching PowerShell and Bash implementations

## Real-World Threat Intelligence

This tool is built directly on documented attack patterns from:

- **CISA Alert AA26-097A** (July 30, 2026) — Water sector PLC targeting advisory
- **FBI PSA 2026-08-01** — Iran-linked threat actors exploiting exposed VNC
- **CISA/EPA Joint Advisory** — Internet-exposed HMIs in water systems
- **July 2026 Minnesota Water Sector Attacks** — 30+ utilities disrupted in a single coordinated campaign

## Key Features

### Threat Detection Prioritized by Real Attack Data
| Port | Protocol | Threat Context |
|------|----------|-----------------|
| 3389 | RDP (Remote Desktop) | PRIMARY ATTACK VECTOR — 70% of water sector breaches (CISA 2026) |
| 5900 / 5901 | VNC | Active exploitation by Iran-linked groups (FBI PSA 2026-08-01) |
| 22 | SSH | CISA-flagged in July 2026 water sector attacks |
| 44818 / 2222 | EtherNet/IP (CIP) | Rockwell MicroLogix 1400 targeted (4,148 exposed globally) |
| 502 | Modbus TCP | Unauthenticated protocol (CVSS 9.3) |
| 102 | S7 Comm | Siemens SIMATIC S7-1200 (4,117 exposed globally) |
| 20000 | DNP3 | Water sector SCADA protocol, no built-in encryption |

### Vendor-Specific Exposure Intelligence
- **Rockwell / Allen-Bradley**: 4,148 exposed hosts globally (71% in the US) — MicroLogix 1400, CompactLogix
- **Siemens**: 4,117 exposed hosts (86% in Europe) — S7-1200 PLCs
- **Schneider Electric**: 2,072 exposed hosts — Modicon M241/M251/M258

## Quick Start

### PowerShell Version (Windows)
```powershell
.\scripts\powershell\WUP-WUP.ps1
```

### Bash Version (Linux/macOS)
```bash
chmod +x scripts/bash/WUP-WUP.sh
./scripts/bash/WUP-WUP.sh
```

Both versions deliver identical scanning logic, threat intelligence, and reporting — choose whichever matches your operating system.

## What This Does NOT Do

- ❌ Does NOT test credentials or attempt authentication
- ❌ Does NOT modify system configurations
- ❌ Does NOT scan IT networks (OT/SCADA focus only)
- ❌ Does NOT replace professional penetration testing
- ❌ Does NOT detect active malware or intrusions
- ❌ Does NOT work over IPv6 (IPv4 only)
- ❌ Does NOT scan non-/24 subnets

## Repository Structure

```
water-utility-protector/
├── scripts/
│   ├── powershell/
│   │   ├── WUP-WUP.ps1
│   │   └── README.md
│   └── bash/
│       ├── WUP-WUP.sh
│       └── README.md
├── docs/
│   ├── CISA-Reference.md
│   └── Threat-Intelligence.md
├── reports/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
└── SECURITY.md
```

## Documentation

- **[PowerShell Guide](scripts/powershell/README.md)** — Windows implementation details
- **[Bash Guide](scripts/bash/README.md)** — Linux/macOS implementation details
- **[CISA Reference](docs/CISA-Reference.md)** — Official CISA guidance and reporting contacts
- **[Threat Intelligence](docs/Threat-Intelligence.md)** — Detailed attack pattern analysis
- **[Security Policy](./SECURITY.md)** — Responsible disclosure

## Technical Specifications

### Supported Platforms
| Platform | Script | Requirements |
|----------|--------|---------------|
| Windows | PowerShell (`WUP-WUP.ps1`) | PowerShell 5.1+, .NET Framework 4.7+ |
| Linux | Bash (`WUP-WUP.sh`) | Bash 4.0+, standard utilities |
| macOS | Bash (`WUP-WUP.sh`) | Bash 4.0+, standard utilities |

### Limitations
- TCP port scan only (no UDP, no banner grabbing)
- Single-threaded (~2–5 minutes per /24 subnet)
- May produce false negatives behind aggressive firewalls
- Requires local network access to the OT subnet being scanned

## Sample Output

```
[!!! CRITICAL !!!] 192.168.10.78:5900 - VNC (Virtual Network Computing)
    Active exploitation by Iran-linked groups (FBI PSA 2026-08-01)
    Action: BLOCK IMMEDIATELY or restrict to VPN only

[!! HIGH !!] 192.168.10.102:44818 - EtherNet/IP (CIP)
    Rockwell MicroLogix 1400 targeted (4,148 exposed globally)
    Action: Restrict to engineering VLAN; implement MFA
```

---

## FAQ

**Q: Do I need admin or root privileges to run WUP WUP?**  
A: No. It uses standard TCP connections. No raw sockets, no elevated privileges needed.

**Q: Can I run this without coordinating with operations?**  
A: No. Port scanning can trigger SCADA alarms and PLC watchdog resets. Always coordinate with your water operations team and get written authorization before scanning any production OT network.

**Q: Does this tool exploit CVEs or attempt to hack PLCs?**  
A: No. WUP WUP only checks whether ports are reachable. It never sends exploit payloads, attempts logins, or modifies any device.

**Q: Can I report results directly to CISA?**  
A: Yes. If you discover actively exploited internet-facing OT devices, you can report directly via [CISA's reporting portal](https://www.cisa.gov/report). The CISA Reference guide in `docs/` includes reporting steps.

**Q: Is this aligned with CISA's water sector recommendations?**  
A: Yes. Every detection category maps directly to CISA Alert AA26-097A remediation guidance.

**Q: Can small rural water systems with no IT staff use this?**  
A: Yes. Both scripts require no installation. Copy to any Windows or Linux machine with network access to the OT subnet and run.

**Q: Is it free?**  
A: Yes — MIT License, free for all use including commercial and government.

---

## Who This Is For

- **Water utility IT/OT teams** at municipal, county, and rural water authorities
- **Wastewater treatment plant operators** needing a fast OT exposure check
- **State drinking water program coordinators** helping small utilities comply with CISA guidance
- **CISA/EPA regional advisors** supporting water sector cybersecurity assessments
- **ICS/OT security consultants** adding water sector capabilities to their service offering
- **Rural water associations** and state primacy agencies supporting small systems

---

## ⭐ Support This Project

If WUP WUP helped your utility find a real exposure, consider:

- ⭐ **Starring this repo** — it helps other water utility security teams find it
- 🐛 **Opening an issue** if you find a bug or want a new detection added
- 🤝 **Contributing** — see [CONTRIBUTING.md](./CONTRIBUTING.md)
- 💬 **Sharing** with your state water association, ISAC, or EPA regional office

> Built by [@spinfosecurity](https://github.com/spinfosecurity) — learning by building free tools that detect and protect critical infrastructure.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome from the water sector cybersecurity community! Please read the [Contributing Guide](CONTRIBUTING.md) first.

## Issues & Support

- **Bug Reports / Feature Requests**: [Open an issue](https://github.com/spinfosecurity/water-utility-protector/issues)
- **Security vulnerabilities in this tool**: See [SECURITY.md](./SECURITY.md)

## References

- [CISA Alert AA26-097A](https://www.cisa.gov/news-events/alerts/2026/07/30/cisa-urges-water-and-wastewater-systems-sector-protect-operational)
- [FBI IC3](https://www.ic3.gov)
- [EPA Water Sector Cybersecurity](https://www.epa.gov/watercybersecurity)
- [CISA Cyber Hygiene Services](https://www.cisa.gov/cyber-hygiene-services)
- [Security Policy](./SECURITY.md)

## Disclaimer

This tool is for **defensive security assessment by authorized personnel only**. Only scan networks you own or have explicit written permission to test. Unauthorized scanning may violate federal and state laws, including the Computer Fraud and Abuse Act (CFAA).

---

**WUP WUP** — Because when your water utility's security matters, you need emergency response, not false alarms.

Made by [spinfosecurity](https://github.com/spinfosecurity)
