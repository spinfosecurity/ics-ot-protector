# ICS OT Protector — Unified Critical Infrastructure Scanner Portfolio

**For employers:** [5-minute code review guide](docs/for-employers.md) · [Portfolio site](https://spinfosecurity.github.io) · **Release:** [v4.4.0](docs/releases/v4.4.0.md)

**ICS OT Protector** is a free, open-source collection of sector-specific OT/SCADA cybersecurity scanners. Each scanner targets the protocols, vendor CVEs, and attack patterns relevant to its critical infrastructure sector — all from a single monorepo with shared governance, CI, and safety documentation.

Previously distributed as four separate repositories, all scanners now live here:

| Sector | Scanner | Monorepo integration | Platforms |
|--------|---------|----------------------|-----------|
| Water & Wastewater | [WUP WUP](scanners/water/) | Shared engine, interactive + scan mode | PowerShell + Bash |
| Power Grid & Substation | [Energy Grid Protector (EGP)](scanners/energy-grid/) | Shared engine, CLI + scan mode | PowerShell + Bash |
| Building Automation (BAS) | [BAS Guardian](scanners/bas/) | Shared engine, interactive + scan mode | PowerShell + Bash |
| Rail & Transit | [Rail-OT-Protector (ROP)](scanners/rail/) | Shared engine, CLI + scan mode | PowerShell + Bash |

### Engineering highlights (for reviewers)

| Area | Evidence |
|------|----------|
| Shared scan pipeline | `scanners/_shared/` — engine, preflight, export, remediation metadata |
| CI & tests | `.github/workflows/ci.yml`, `tests/shared/` |
| Operator safety | `docs/safe-operation.md`, `docs/threat-model.md` |
| Reporting | `docs/sample-report.json`, `scripts/review_scan_report.sh` |

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Bash](https://img.shields.io/badge/Bash-4.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![CISA Aligned](https://img.shields.io/badge/CISA-ICS%20Advisories%20Aligned-red)](#)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)]()
[![GitHub issues](https://img.shields.io/github/issues/spinfosecurity/ics-ot-protector)](https://github.com/spinfosecurity/ics-ot-protector/issues)
[![GitHub stars](https://img.shields.io/github/stars/spinfosecurity/ics-ot-protector?style=social)](https://github.com/spinfosecurity/ics-ot-protector/stargazers)

---

## About

Critical infrastructure operators across water, energy, building automation, and rail sectors face escalating cyberattacks targeting exposed PLCs, HMIs, and remote access systems. Each sector scanner in this portfolio implements **sector-specific port coverage, threat intelligence, and remediation guidance** drawn from CISA ICS advisories, FBI PSAs, and vendor CVE databases.

All scanners share a defensive posture: **TCP port reachability checks only** — no credential testing, no exploit payloads, no configuration changes.

**Keywords:** ICS security scanner, OT vulnerability scanner, SCADA exposure assessment, critical infrastructure protection, CISA AA26-097A, PowerShell ICS scanner, Bash SCADA scanner, water utility cybersecurity, power grid OT security, BACnet scanner, rail OT security

---

## Quick Start

### Unified launcher (all sectors)

```powershell
# PowerShell — interactive sector scanner
.\scripts\ics-ot-protector.ps1 -Sector water
.\scripts\ics-ot-protector.ps1 -Sector energy-grid -Subnet 192.168.10.0/24

# PowerShell — non-interactive scan mode (all sectors, shared engine)
pwsh .\scripts\ics-ot-protector.ps1 -Scan -ScanSector energy-grid -Subnets 192.168.10.0/24 -CveOnly
```

```bash
# Bash — interactive sector scanner
./scripts/ics-ot-protector.sh water
./scripts/ics-ot-protector.sh energy-grid -s 192.168.10.0/24

# Bash — non-interactive scan mode (all sectors, shared engine)
./scripts/ics-ot-protector.sh scan --sector rail --subnets 10.10.20.0/24
./scripts/ics-ot-protector.sh scan --sector energy-grid --subnets 192.168.10.0/24 --cve-only
```

**Scan mode** runs pre-flight checks (dependencies, CIDR validation, host-count limits), uses the shared TCP scan engine, and writes JSON plus CSV reports with a `metadata.summary` block (hosts scanned, probes, findings by severity, duration). Use `--force` / `-Force` for large subnets (/16 and below) or scopes above 4096 hosts; use `--no-csv` / `-NoCsv` to skip CSV export; use `--config` / `-Config` to merge a YAML/JSON port profile overlay; use `--quiet` / `-Quiet` to suppress progress output.

**Dependencies (scan mode):** Bash scan mode requires `jq` and `timeout` (coreutils). PowerShell scan mode requires PowerShell 5.1+ with built-in JSON cmdlets.

Pick a sector scanner directly:


### Water & Wastewater — WUP WUP
```powershell
# PowerShell (interactive wizard)
.\scanners\water\powershell\WUP-WUP.ps1
```
```bash
# Bash (interactive wizard)
./scanners/water/bash/WUP-WUP.sh
```

### Power Grid & Substation — EGP
```powershell
.\scanners\energy-grid\powershell\EGP.ps1 -Subnet 192.168.10.0/24
```
```bash
./scanners/energy-grid/bash/EGP.sh 192.168.10.0/24
```

### Building Automation — BAS Guardian
```powershell
.\scanners\bas\powershell\BAS-Guardian.ps1
```
```bash
./scanners/bas/bash/BAS-Guardian.sh
```

### Rail & Transit — ROP
```powershell
pwsh ./scanners/rail/powershell/ROP.ps1 -Subnets 10.10.20.0/24
```
```bash
./scanners/rail/bash/ROP.sh 10.10.20.0/24
```

> **Backward compatibility:** The water scanner's legacy paths (`scripts/powershell/WUP-WUP.ps1` and `scripts/bash/WUP-WUP.sh`) still work and redirect to the canonical location.

All scanners export findings as **JSON** (`schema_version` 1.0) with sector metadata, an optional **`metadata.summary`** block (scan stats and severity counts), and a normalized findings array. Non-interactive **scan mode** also writes a companion **CSV** file by default.

---

## Architecture

Sector scanners share a common scan pipeline under `scanners/_shared/`:

| Module | Bash | PowerShell |
|--------|------|------------|
| Scan engine | `scan_engine.sh` | `ScanEngine.ps1` |
| Pre-flight validation | `preflight.sh` | `Preflight.ps1` |
| Report export | `export_scan_report.sh` | `Export-ScanReport.ps1` |
| Sector config | `load_sector_config.sh` | `Import-SectorConfig.ps1` |
| Non-interactive runner | `run_sector_scan.sh` | `Run-SectorScan.ps1` |

Interactive sector scanners (WUP WUP, BAS Guardian) retain their wizards; CLI scanners (EGP, ROP) accept subnet arguments directly. **Scan mode** (`./scripts/ics-ot-protector.sh scan …` / `-Scan`) uses the shared engine for all four sectors with consistent reporting and pre-flight scope checks.

---

## What All Scanners Do

- Scan OT subnets for internet-exposed PLCs, HMIs, and remote access points
- Detect primary attack vectors: RDP (3389), VNC (5900), SSH (22)
- Identify sector-specific OT protocol exposure
- Prioritize findings by severity (CRITICAL / HIGH / MEDIUM)
- Provide CISA-aligned remediation guidance
- Generate reports for sharing with IT and OT teams

## What They Do NOT Do

- ❌ Do NOT test credentials or attempt authentication
- ❌ Do NOT modify system configurations
- ❌ Do NOT replace professional penetration testing
- ❌ Do NOT detect active malware or intrusions
- ❌ Do NOT work over IPv6 (IPv4 only)

---

## Repository Structure

```
ics-ot-protector/
├── scanners/
│   ├── water/              # WUP WUP — water & wastewater
│   ├── energy-grid/        # EGP — power grid & substation
│   ├── bas/                # BAS Guardian — building automation
│   └── rail/               # ROP — rail & transit
├── docs/
│   ├── sectors/            # Sector-specific threat intel & reports
│   ├── safe-operation.md   # Shared authorized-use procedures
│   ├── threat-model.md     # Shared scope & limitations
│   ├── sample-report.md    # JSON export format reference
│   └── sample-report.json  # Example scan report (schema v1.0)
├── tests/
│   ├── shared/             # Monorepo-wide validation + shared engine tests
│   ├── water/              # WUP WUP behavioral + repo tests
│   ├── energy-grid/
│   ├── bas/
│   └── rail/
├── scripts/                # Backward-compat launchers (water only)
├── reports/
└── README.md
```

---

## Documentation

### Shared
- [For employers and hiring managers](docs/for-employers.md)
- [Safe Operation Guide](docs/safe-operation.md)
- [Threat Model](docs/threat-model.md)
- [Sample Report Format](docs/sample-report.md) · [Example JSON](docs/sample-report.json) · [Offline report review](docs/report-review-workflow.md)
- [Repository Migration Guide](docs/repository-migration.md)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)

### Sector-Specific
| Sector | Guide | Threat Intel | CISA Reference |
|--------|-------|-------------|----------------|
| Water | [README](scanners/water/README.md) | [Threat-Intelligence](docs/sectors/water/Threat-Intelligence.md) | [CISA-Reference](docs/sectors/water/CISA-Reference.md) |
| Energy Grid | [README](scanners/energy-grid/README.md) | — | — |
| BAS | [README](scanners/bas/README.md) | [Threat-Intelligence](docs/sectors/bas/Threat-Intelligence.md) | [CISA-Reference](docs/sectors/bas/CISA-Reference.md) |
| Rail | [README](scanners/rail/README.md) | [Threat-Intelligence](docs/sectors/rail/Threat-Intelligence.md) | [CISA-Reference](docs/sectors/rail/CISA-Reference.md) |

---

## FAQ

**Q: Which scanner should I use?**  
A: Match your sector — water utilities use WUP WUP, power grid operators use EGP, facility managers use BAS Guardian, and rail/transit authorities use ROP. Each scanner has sector-specific port tables and threat intelligence.

**Q: Do I need admin or root privileges?**  
A: No. All scanners use standard TCP connections. No raw sockets or elevated privileges needed.

**Q: Can I run these without coordinating with operations?**  
A: No. Port scanning can trigger SCADA alarms and PLC watchdog resets. Always coordinate with your operations team and get written authorization before scanning any production OT network.

**Q: Are the old separate repos still maintained?**  
A: No. `Energy-Grid-Protector`, `BAS-Guardian`, and `Rail-OT-Protector` are being archived in favor of this monorepo at [`spinfosecurity/ics-ot-protector`](https://github.com/spinfosecurity/ics-ot-protector). See [Repository Migration Guide](docs/repository-migration.md) for archive instructions.

**Q: Is it free?**  
A: Yes — MIT License, free for all use including commercial and government.

---

## Who This Is For

- **Water utility IT/OT teams** — municipal, county, and rural water authorities
- **Power grid and substation operators** — transmission and distribution utilities
- **Facility managers and BAS teams** — commercial, healthcare, and data center buildings
- **Rail and transit authorities** — passenger and freight OT/SCADA networks
- **CISA/EPA regional advisors** and **ICS/OT security consultants**

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

These tools are for **defensive security assessment by authorized personnel only**. Only scan networks you own or have explicit written permission to test. Unauthorized scanning may violate federal and state laws, including the Computer Fraud and Abuse Act (CFAA).

---

Made by [@spinfosecurity](https://github.com/spinfosecurity)
