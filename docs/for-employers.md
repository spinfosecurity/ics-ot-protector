# Reviewing this repo for a role

If you're hiring for OT/ICS security, security automation, or analyst work with a scripting bent, this page is a quick map to the public code.

**Portfolio:** [spinfosecurity.github.io](https://spinfosecurity.github.io)  
**Repo:** [github.com/spinfosecurity/ics-ot-protector](https://github.com/spinfosecurity/ics-ot-protector)  
**Latest release:** [v4.4.1](releases/v4.4.1.md)

---

## What you'll find here

ICS OT Protector is a monorepo of defensive OT/SCADA scanners in PowerShell and Bash. Four sectors share one scan engine, one export format, and one CI pipeline. The tools do TCP reachability checks on authorized networks — no credentials, no exploit code.

Good places to start:

- **[README.md](../README.md)** — layout and how to run a scan
- **`scanners/_shared/`** — engine, preflight checks, JSON export
- **`scanners/water/`** — the most complete scanner, with behavioral tests
- **`config/sectors/`** — port catalogs and sector context (Modbus, DNP3, BACnet, etc.)
- **`docs/safe-operation.md`** and **`docs/threat-model.md`** — scope and limits
- **[Actions](https://github.com/spinfosecurity/ics-ot-protector/actions)** — CI on `main`

---

## Try the output without scanning anything

```bash
git clone https://github.com/spinfosecurity/ics-ot-protector.git
cd ics-ot-protector
./scripts/review_scan_report.sh docs/sample-report.json
```

That runs the same triage view an analyst would use after a real scan. Sample JSON is in `docs/sample-report.json`.

---

## Resume bullets (starting points)

These describe what the repos show — not job titles I've held. Edit the wording to match your conversation.

- Built ICS OT Protector, an open-source monorepo of OT exposure scanners for water, energy, BAS, and rail (PowerShell + Bash).
- Wrote a shared scan engine with preflight checks, parallel probing, and JSON/CSV reports used across all four sectors.
- Added remediation metadata and a small offline review CLI so findings are easier to hand off to OT teams.
- Kept CI green with Bash and Pester tests, config drift checks, and ScriptAnalyzer on the PowerShell side.
- Documented authorized-use limits up front — TCP reachability only, aligned with public CISA/ICS guidance.

Generate bullets from your own report JSON:

```bash
./scripts/resume-bullets-from-report.sh docs/sample-report.json
```

---

## Roles this maps to

OT/ICS security, security automation, and analyst roles where PowerShell or Bash and some protocol familiarity (Modbus, DNP3, BACnet) matter.

---

## Contact

GitHub is the easiest path: [github.com/spinfosecurity](https://github.com/spinfosecurity)

---

## Limits (worth stating clearly)

Not an exploit framework, credential tester, pentest replacement, or malware scanner. Run only on networks you're authorized to assess.
