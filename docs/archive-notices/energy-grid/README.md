# ⚠️ Repository Archived

This repository has been **archived** and is no longer maintained.

All development continues in the unified **ICS OT Protector** monorepo:

**https://github.com/spinfosecurity/water-utility-protector**

## Where to find this scanner

| Former repo | New location |
|-------------|--------------|
| Energy-Grid-Protector | [`scanners/energy-grid/`](https://github.com/spinfosecurity/water-utility-protector/tree/main/scanners/energy-grid) |
| BAS-Guardian | [`scanners/bas/`](https://github.com/spinfosecurity/water-utility-protector/tree/main/scanners/bas) |
| Rail-OT-Protector | [`scanners/rail/`](https://github.com/spinfosecurity/water-utility-protector/tree/main/scanners/rail) |
| water-utility-protector | [`scanners/water/`](https://github.com/spinfosecurity/water-utility-protector/tree/main/scanners/water) |

## Quick start (Energy Grid Protector)

```powershell
# PowerShell
git clone https://github.com/spinfosecurity/water-utility-protector.git
cd ics-ot-protector
.\scanners\energy-grid\powershell\EGP.ps1 -Subnet 192.168.10.0/24
```

```bash
# Bash
git clone https://github.com/spinfosecurity/water-utility-protector.git
cd ics-ot-protector
./scanners/energy-grid/bash/EGP.sh 192.168.10.0/24
```

## Issues and contributions

Please open issues and pull requests on the monorepo:

**https://github.com/spinfosecurity/water-utility-protector/issues**

---

*Archived by [spinfosecurity](https://github.com/spinfosecurity). GitHub automatically redirects this repository URL until the rename is complete.*
