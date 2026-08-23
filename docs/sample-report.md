# Sample Report

All ICS OT Protector scanners export findings as **JSON** using `schema_version` 1.0.

Synthetic example only — addresses and findings are fictional. See [sample-report.json](sample-report.json) for the full document.

## Schema

| Field | Description |
|-------|-------------|
| `schema_version` | Always `"1.0"` for current exports |
| `generated_at` | ISO-style timestamp when the report was written |
| `metadata` | Sector, scanner name, scan configuration, and optional summary |
| `metadata.summary` | Scan statistics (see below) — included in scan mode and when stats are provided at export |
| `findings[]` | Normalized finding objects (see below) |

### Summary block (`metadata.summary`)

| Field | Description |
|-------|-------------|
| `hosts_scanned` | Unique IPv4 hosts probed |
| `ports_checked` | Ports in the sector catalog for this run |
| `probes_total` | Approximate host × port probe count |
| `findings_total` | Number of open-port findings |
| `findings_by_severity` | Counts keyed by severity (`CRITICAL`, `HIGH`, `MEDIUM`, …) |
| `duration_ms` | Wall-clock scan duration in milliseconds |

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

## JSON and CSV

- **JSON** is the canonical export for sharing with IT/OT teams, ticketing systems, or downstream tooling.
- **CSV** is written alongside JSON in non-interactive **scan mode** by default (same timestamped basename). Columns: `Timestamp`, `Host`, `Port`, `Service`, `Severity`, `Category`, `Description`, `Remediation`. Pass `--no-csv` (Bash) or `-NoCsv` (PowerShell) to skip CSV.

## Console vs file output

Console output remains color-coded and human-readable during the scan. The JSON file is the canonical structured export.

## Triage workflow

1. Confirm scope and asset owner for each `Host`.
2. Review `metadata.summary` for scope confirmation (hosts, probes, duration).
3. Validate with engineering — reachability is an exposure candidate, not proof of compromise.
4. Assess segmentation, remote access, and firewall rules.
5. Create a ticket with the JSON (or CSV) evidence, owner, and due date.
6. Rescan only with authorization after remediation.

## Sector examples

- [Water sample report](sectors/water/sample-report.md)
- [Energy grid sample report](sectors/energy-grid/sample-report.md)
- [BAS sample report](sectors/bas/sample-report.md)
- [Rail sample report](sectors/rail/sample-report.md)
