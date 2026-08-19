# Sample Report

All ICS OT Protector scanners export findings as **JSON** using `schema_version` 1.0.

Synthetic example only — addresses and findings are fictional. See [sample-report.json](sample-report.json) for the full document.

## Schema

| Field | Description |
|-------|-------------|
| `schema_version` | Always `"1.0"` for current exports |
| `generated_at` | ISO-style timestamp when the report was written |
| `metadata` | Sector, scanner name, scan configuration, summary counts |
| `findings[]` | Normalized finding objects (see below) |

Each finding object:

| Field | Description |
|-------|-------------|
| `Timestamp` | When the port was observed open |
| `Host` | Target IPv4 address |
| `Port` | TCP port number |
| `Service` | Human-readable service or finding label |
| `Severity` | `CRITICAL`, `HIGH`, or `MEDIUM` |
| `Category` | e.g. Remote Access, OT Protocol Exposure, CVE |
| `Description` | Threat context or exposure rationale |
| `Remediation` | Recommended defensive action |

## Console vs file output

Console output remains color-coded and human-readable during the scan. The JSON file is the canonical export for sharing with IT/OT teams, ticketing systems, or downstream tooling.

## Triage workflow

1. Confirm scope and asset owner for each `Host`.
2. Validate with engineering — reachability is an exposure candidate, not proof of compromise.
3. Assess segmentation, remote access, and firewall rules.
4. Create a ticket with the JSON evidence, owner, and due date.
5. Rescan only with authorization after remediation.

## Sector examples

- [Water sample report](sectors/water/sample-report.md)
- [Energy grid sample report](sectors/energy-grid/sample-report.md)
- [BAS sample report](sectors/bas/sample-report.md)
- [Rail sample report](sectors/rail/sample-report.md)
