# Sample Report — Water & Wastewater

Synthetic example only. Full JSON schema reference: [docs/sample-report.json](../../sample-report.json).

Report prefix: `WUP-results-*.json`  
Default location: `~/WaterUtilitySecurity/Reports/`

Example finding from a water scan:

```json
{
  "Host": "192.168.10.78",
  "Port": 5900,
  "Service": "VNC (Virtual Network Computing)",
  "Severity": "CRITICAL",
  "Category": "Remote Access",
  "Description": "VNC exposed — primary ransomware entry vector per CISA AA26-097A",
  "Remediation": "BLOCK IMMEDIATELY or restrict to VPN only"
}
```

Triage: confirm scope/owner; validate with engineering; assess segmentation and remote access; attach the JSON report to your ticket; rescan only with authorization.
