# For employers and hiring managers

**Portfolio:** [spinfosecurity.github.io](https://spinfosecurity.github.io)  
**Flagship repo:** [github.com/spinfosecurity/ics-ot-protector](https://github.com/spinfosecurity/ics-ot-protector)  
**Current release:** v4.4.0

This page is a **5-minute review guide** for recruiters and hiring managers evaluating OT/ICS security or security-automation candidates. Everything linked here is public code—not slideware.

---

## What this demonstrates

| Skill area | Where to look | What you should see |
|------------|---------------|---------------------|
| OT/ICS domain awareness | `config/sectors/*.yaml` | Sector port catalogs (Modbus, DNP3, BACnet, remote access) mapped to CISA-oriented context |
| Security automation | `scanners/_shared/scan_engine.sh`, `ScanEngine.ps1` | Shared TCP scan engine in Bash and PowerShell |
| Engineering discipline | `.github/workflows/ci.yml`, `tests/` | Pester + Bash tests, config drift checks, linting |
| Operator safety | `docs/safe-operation.md`, `docs/threat-model.md` | Authorized-use scope, explicit non-goals |
| Reporting for triage | `docs/sample-report.json`, `scripts/review_scan_report.sh` | JSON schema, remediation metadata, offline review CLI |

---

## 5-minute review path

1. **Start here:** [README.md](../README.md) — architecture and quick start  
2. **Scan pipeline:** `scanners/_shared/` — shared engine, preflight, export  
3. **One sector deep-dive:** `scanners/water/` (most mature interactive scanner + behavioral tests)  
4. **Sample output:** [docs/sample-report.json](sample-report.json) + run review CLI below  
5. **CI proof:** [Actions tab](https://github.com/spinfosecurity/ics-ot-protector/actions) — green validate workflow on `main`

---

## Demo: scan output → triage (no network required)

Review a sample report the same way an analyst would after a scan:

```bash
git clone https://github.com/spinfosecurity/ics-ot-protector.git
cd ics-ot-protector
./scripts/review_scan_report.sh docs/sample-report.json
```

Markdown triage summary:

```bash
./scripts/review_scan_report.sh docs/sample-report.json --markdown
```

Generate copy-paste resume bullets from any schema 1.0 report:

```bash
./scripts/resume-bullets-from-report.sh docs/sample-report.json
```

---

## Sample resume bullets (honest framing)

Use these as templates—adjust to your interview narrative. They describe **what the public repos prove**, not prior employer titles.

- Built **ICS OT Protector**, an open-source monorepo of defensive OT/SCADA exposure scanners covering water, energy, BACnet/BMS, and rail sectors (PowerShell + Bash, MIT license).
- Implemented a **shared scan engine** with preflight validation, parallel host×port probing, and severity-ranked JSON/CSV reporting used across four sector scanners.
- Mapped **CISA-aligned remediation guidance** into structured finding metadata (`RemediationPriority`, `OwnerRole`) and offline triage CLI helpers for IT/OT handoff.
- Maintained **CI-validated tooling** (Pester + Bash integration tests, config drift guards, ScriptAnalyzer lint) for cross-platform Windows/Linux operator use.
- Documented **authorized-use boundaries** and threat models for critical-infrastructure scanning—TCP reachability only, no credential testing or exploit payloads.

---

## Roles this work supports discussing

- OT / ICS security (exposure discovery, advisory mapping, defensive tooling)
- Security automation / SOAR-adjacent scripting (PowerShell, Bash, JSON reporting)
- Cybersecurity analyst paths where industrial protocol awareness matters

---

## Contact

- **GitHub:** [github.com/spinfosecurity](https://github.com/spinfosecurity)  
- **Portfolio:** [spinfosecurity.github.io](https://spinfosecurity.github.io)  
- **Hiring inquiries:** open a GitHub issue on this repo with label `hiring` or contact via the GitHub profile

---

## What this is not

These projects are **not** an exploit framework, credential tester, penetration-testing substitute, or malware detector. They must not be run without explicit asset-owner authorization.
