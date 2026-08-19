# Sample Report — Building Automation (BAS)

Synthetic example only. Full JSON schema reference: [docs/sample-report.json](../../sample-report.json).

Report prefix: `BAS-results-*.json`  
Default location: `./reports/`

Example finding from a BAS scan:

```json
{
  "Host": "172.16.5.42",
  "Port": 47808,
  "Service": "BACnet/IP (UDP/TCP)",
  "Severity": "HIGH",
  "Category": "BAS Exposure",
  "Description": "BACnet/IP exposed — unauthenticated device discovery risk",
  "Remediation": "Remove from internet; segment from IT network; patch bacnet-stack"
}
```

Triage: confirm BMS owner; check for unauthorized Who-Is/I-Am traffic; validate with facilities engineering; rescan only with authorization.
