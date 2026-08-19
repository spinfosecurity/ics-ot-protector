# Sample Report

This synthetic example illustrates the reporting workflow. The addresses, timestamps, and findings below are fictional and must not be treated as live intelligence.

```text
[CRITICAL] 10.10.20.14:4510  Potential EOT/HOT remote-linking service exposure candidate
[HIGH]     10.10.20.21:5900  VNC reachable from the authorized scan host
[HIGH]     10.10.20.44:2404  IEC 60870-5-104 reachable from the authorized scan host
[MEDIUM]   10.10.20.88:22    SSH reachable; review access policy
```

## Triage Workflow

1. Confirm the target is in scope and identify its owner.
2. Validate the service with the responsible engineering and security teams.
3. Assess segmentation, remote-access controls, monitoring, and compensating safeguards.
4. Create a remediation ticket with the sanitized evidence and an agreed owner/date.
5. Rescan only after authorization to confirm remediation.

## Example Ticket Fields

| Field | Example |
|---|---|
| Asset | Transit operations jump host |
| Evidence | Reachable TCP/5900 from approved scanner |
| Severity | High |
| Recommended action | Restrict VNC to managed access path; require approved remote-access controls |
| Validation | Engineering confirms service owner and remediation window |
