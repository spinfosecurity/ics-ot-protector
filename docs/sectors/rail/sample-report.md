# Sample Report — Rail & Transit

Synthetic example only. Full JSON schema reference: [docs/sample-report.json](../../sample-report.json).

Report prefix: `ROP-results-*.json`  
Default location: `./reports/`

Example finding from a rail scan:

```json
{
  "Host": "10.10.30.12",
  "Port": 4510,
  "Service": "EOT Remote Link",
  "Severity": "CRITICAL",
  "Category": "EotHot",
  "Description": "CVE-2025-1727 EOT/HOT weak authentication indicator",
  "Remediation": ""
}
```

Triage: confirm signaling/SCADA owner; reference CISA AA26-097A and FBI PSA 2026-08-01; validate EOT/HOT configuration; rescan only with authorization.
