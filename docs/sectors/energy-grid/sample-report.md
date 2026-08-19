# Sample Report — Power Grid & Substation

Synthetic example only. Full JSON schema reference: [docs/sample-report.json](../../sample-report.json).

Report prefix: `EGP-results-*.json`  
Default location: `./reports/`

Example finding from an energy-grid scan:

```json
{
  "Host": "10.10.20.15",
  "Port": 443,
  "Service": "CVE-2026-42945",
  "Severity": "CRITICAL",
  "Category": "CVE",
  "Description": "Hitachi Energy web management interface exposure candidate",
  "Remediation": "Apply vendor patch; restrict management VLAN access"
}
```

Triage: confirm asset owner and vendor; cross-reference CISA ICS advisories; validate before treating as exploitable; rescan only with authorization.
