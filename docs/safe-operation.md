# Safe Operation

ICS OT Protector scanners are defensive exposure-discovery tools for **authorized OT/SCADA assessments only**. They are not exploit frameworks and must not be used without explicit written permission.

## Before You Scan

1. Obtain written authorization that defines approved subnets, maintenance window, scan host, contacts, and stop conditions.
2. Coordinate with operations, network teams, cybersecurity, and the control-system or asset owner for your sector.
3. Confirm the scan host has an approved network path and that monitoring teams understand the activity.
4. Start with the smallest approved scope and conservative timeout/concurrency settings.
5. Record a stop contact and stop condition before beginning.

## During a Scan

- Scan only approved addresses and ports.
- Do not attempt credentials, authentication bypasses, exploit payloads, configuration changes, or device commands.
- Monitor controller, HMI, network, and safety alarms for unexpected behavior.
- Stop immediately if operations report instability, latency, alarms, or unexpected device behavior.

## After a Scan

- Treat a reachable service as an **exposure candidate**, not proof of a vulnerable or compromised asset.
- Validate findings through approved engineering and security workflows.
- Store JSON reports according to your organization's data-handling policy.
- Create tickets with asset owner, network location, evidence, severity rationale, and recommended remediation.

## Emergency Stop

Terminate the scanner with `Ctrl+C`, notify the designated operations contact, preserve the partial JSON report if one was written, and document the reason for stopping.

## Sector Addenda

Sector-specific coordination notes:

- [Water & Wastewater](sectors/water/safe-operation.md)
- [Power Grid & Substation](sectors/energy-grid/safe-operation.md)
- [Building Automation (BAS)](sectors/bas/safe-operation.md)
- [Rail & Transit](sectors/rail/safe-operation.md)
