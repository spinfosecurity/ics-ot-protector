#!/bin/bash
set -euo pipefail

REPO_NAME="water-utility-protector"
GITHUB_USER="spinfosecurity"
REPO_URL="https://github.com/$GITHUB_USER/$REPO_NAME"

echo "================================================================================"
echo "  Water Utility Protector - GitHub Repository Setup"
echo "================================================================================"

echo "[1/8] Creating directory structure..."
mkdir -p scripts/powershell
mkdir -p scripts/bash
mkdir -p reports
mkdir -p .github/ISSUE_TEMPLATE
mkdir -p .github/PULL_REQUEST_TEMPLATE
mkdir -p docs/images

echo "[2/8] Creating SEO-optimized README.md..."
cat > README.md << 'README_EOF'
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
README_EOF

echo "[3/8] Creating MIT LICENSE..."
cat > LICENSE << 'LICENSE_EOF'
MIT License

Copyright (c) 2026 Shannon P.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
LICENSE_EOF

echo "[4/8] Creating .gitignore..."
cat > .gitignore << 'GITIGNORE_EOF'
.DS_Store
Thumbs.db
desktop.ini
*.swp
*.swo
*~
.vscode/
.idea/
*.log
logs/
reports/*.txt
reports/*.csv
reports/*.json
reports/*.html
tmp/
temp/
*.tmp
*.env
node_modules/
dist/
build/
*.zip
*.tar.gz
GITIGNORE_EOF

echo "[5/8] Creating CONTRIBUTING.md..."
cat > CONTRIBUTING.md << 'CONTRIB_EOF'
# Contributing to Water Utility Protector

Thank you for your interest in contributing to WUP WUP!

## How to Contribute

### Reporting Bugs
Open an issue with steps to reproduce, expected vs actual behavior, and environment details.

### Pull Requests
1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Make your changes and test on your target platform
4. Commit with clear messages
5. Push and open a Pull Request

### Code Standards

PowerShell: Use approved verbs, comment-based help, parameter validation.
Bash: Use ShellCheck, follow Google Shell Style Guide, use set -euo pipefail.

## Development Setup

```bash
git clone https://github.com/spinfosecurity/water-utility-protector.git
cd water-utility-protector
chmod +x scripts/bash/wup_wup.sh
./scripts/bash/wup_wup.sh
```
CONTRIB_EOF

echo "[6/8] Creating CISA reference documentation..."
cat > docs/CISA-Reference.md << 'CISA_EOF'
# CISA Reference - Water Utility Cybersecurity

## CISA Alert AA26-097A (July 2026)

CISA issued an urgent alert on July 30, 2026, warning water and wastewater utilities about active exploitation of internet-exposed operational technology (OT) assets.

### Key Findings
- 70% of water sector breaches involve RDP exposure
- Iran-linked groups actively exploiting VNC
- Rockwell MicroLogix 1400 specifically targeted (4,148 exposed globally)
- Cellular modems identified as a blind spot in many utilities

### CISA Recommendations
1. Disconnect CRITICAL devices from internet immediately
2. Implement VPN for all remote access (RDP/VNC/SSH)
3. Change ALL default passwords on PLCs/HMIs
4. Restrict OT protocols to engineering VLAN only
5. Check for cellular modem exposure
6. Document findings and report to CISA if compromised

### References
- CISA Alert AA26-097A
- FBI PSA 2026-08-01
- EPA Water Sector Cybersecurity

## CISA Cyber Hygiene Services

Free vulnerability scanning: https://www.cisa.gov/cyber-hygiene-services

## Reporting Incidents

- Phone: 1-844-Say-CISA (1-844-729-2472)
- Online: https://www.cisa.gov/report-cyber-incident
- FBI IC3: https://www.ic3.gov
CISA_EOF

echo "[7/8] Creating threat intelligence documentation..."
cat > docs/Threat-Intelligence.md << 'THREAT_EOF'
# Threat Intelligence - Water Sector Attacks

## July 2026 Water Sector Attacks

Over 30 water utilities in Minnesota were hit by coordinated cyberattacks in July 2026.

### Primary Attack Vectors
1. RDP (Port 3389) - 70% of breaches
2. VNC (Port 5900) - Active exploitation by Iran-linked groups
3. SSH (Port 22) - CISA-flagged

### Targeted Vendors
- Rockwell: 4,148 exposed hosts (71% US) - MicroLogix 1400, CompactLogix
- Siemens: 4,117 exposed hosts (86% Europe) - S7-1200
- Schneider: 2,072 exposed hosts - Modicon M241/M251/M258 (CVSS 9.3)

### OT Protocols Exploited
- EtherNet/IP (44818, 2222)
- Modbus TCP (502)
- DNP3 (20000)
- S7 Comm (102)

### Mitigation Strategies
1. Disconnect exposed devices from internet
2. Implement VPN for all remote access
3. Change all default passwords
4. Enable MFA on all accounts
5. Segment IT and OT networks
THREAT_EOF

echo "[8/8] Creating script placeholders and GitHub templates..."

cat > scripts/powershell/README.md << 'PS_EOF'
# PowerShell Version

Usage:
```powershell
.\WUP-WUP.ps1
```

Requirements: Windows PowerShell 5.1+, .NET Framework 4.7+.
See root README.md for full documentation.
PS_EOF

cat > scripts/bash/README.md << 'BASH_EOF'
# Bash Version

Usage:
```bash
chmod +x wup_wup.sh
./wup_wup.sh
```

Requirements: Bash 4.0+, no external dependencies.
See root README.md for full documentation.
BASH_EOF

cat > .github/ISSUE_TEMPLATE/bug_report.md << 'BUG_EOF'
---
name: Bug Report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
---

**Describe the bug**

**To Reproduce**

**Expected behavior**

**Environment:**
- OS:
- Version:
BUG_EOF

cat > .github/ISSUE_TEMPLATE/feature_request.md << 'FEAT_EOF'
---
name: Feature Request
about: Suggest an idea for this project
title: '[FEATURE] '
labels: enhancement
---

**Describe the feature**

**Use case**
FEAT_EOF

cat > .github/PULL_REQUEST_TEMPLATE.md << 'PR_EOF'
## Description

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update

## Testing
- [ ] Tested on Linux (Bash)
- [ ] Tested on Windows (PowerShell)
PR_EOF

echo ""
echo "================================================================================"
echo "  Repository setup complete!"
echo "================================================================================"
echo ""
echo "Next steps:"
echo "1. Add your scripts:"
echo "   cp /path/to/WUP-WUP.ps1 scripts/powershell/"
echo "   cp /path/to/wup_wup.sh scripts/bash/"
echo ""
echo "2. Initialize Git:"
echo "   git init"
echo "   git add ."
echo "   git commit -m 'Initial commit: Water Utility Protector'"
echo ""
echo "3. Create GitHub repo (requires gh CLI) and push:"
echo "   gh repo create $GITHUB_USER/$REPO_NAME --public --source=. --remote=origin"
echo "   git push -u origin main"
echo ""
echo "   OR manually create the repo on GitHub.com, then:"
echo "   git remote add origin $REPO_URL.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "4. Add topics on GitHub for SEO:"
echo "   water-utility, cybersecurity, ot-security, ics-security,"
echo "   scada-security, cisa, powershell, bash"
echo ""
echo "Your repository is ready!"
