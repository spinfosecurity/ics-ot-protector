# Offline Report Review Workflow

Use this workflow to triage ICS OT Protector scan reports **without re-running the scanner**. This guide covers structured remediation fields introduced in v4.4 and the offline review helpers.

## When to use

- After any scan that produced a JSON report (interactive or scan mode)
- Before opening tickets or briefing OT/engineering teams
- When sharing results with stakeholders who will not run the scanner

## Structured finding fields (v4.4+)

Each finding may include remediation metadata derived from severity and category:

| Field | Values | Meaning |
|-------|--------|---------|
| `RemediationPriority` | `IMMEDIATE`, `URGENT`, `PLANNED` | Triage urgency |
| `RemediationAction` | `block`, `segment`, `patch`, `verify` | Recommended action type |
| `OwnerRole` | `ot`, `it`, `security` | Suggested owning team |

The `metadata.summary` block adds:

| Field | Description |
|-------|-------------|
| `findings_by_category` | Counts by finding category |
| `findings_by_priority` | Counts by remediation priority |
| `findings_by_owner_role` | Counts by suggested owner |
| `top_hosts` | Up to five hosts with the most findings |

## Review steps

1. **Open the JSON report** from `./reports/` (or your configured output directory).
2. **Run the review helper** to produce a triage-oriented summary:

```bash
./scripts/review_scan_report.sh ./reports/WUP-results-20260823-120000.json
```

```powershell
pwsh ./scripts/Review-ScanReport.ps1 -ReportPath .\reports\WUP-results-20260823-120000.json
```

3. **Work IMMEDIATE findings first** — typically internet-exposed remote access (RDP/VNC/SSH).
4. **Assign URGENT items** to OT or security based on `OwnerRole` and `RemediationAction`.
5. **Validate with engineering** — open ports indicate exposure candidates, not confirmed compromise.
6. **Document actions** — note firewall changes, segmentation updates, or patch plans.
7. **Archive the JSON** as evidence; re-scan only with authorization after remediation.

## Markdown export for briefings

```bash
./scripts/review_scan_report.sh ./reports/WUP-results-20260823-120000.json --markdown > triage-brief.md
```

```powershell
pwsh ./scripts/Review-ScanReport.ps1 -ReportPath .\reports\WUP-results-20260823-120000.json -Markdown | Set-Content triage-brief.md
```

## Priority guide

| Priority | Typical categories | First action |
|----------|-------------------|--------------|
| IMMEDIATE | CRITICAL remote access | Block or restrict to VPN/jump host |
| URGENT | OT protocol exposure, CVE | Segment OT VLAN; schedule patch |
| PLANNED | MEDIUM, informational | Verify asset owner; schedule review |

## Related docs

- [Sample report format](sample-report.md)
- [Safe operation guide](safe-operation.md)
- [Threat model](threat-model.md)
