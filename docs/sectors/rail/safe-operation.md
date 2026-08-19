# Safe Operation Guide

## Purpose

Rail-OT-Protector is a defensive exposure-discovery tool for authorized rail and transit OT/SCADA assessments. It is not an exploit framework and must not be used to test systems without explicit authorization.

## Before You Scan

1. Obtain written authorization that identifies the approved subnets, maintenance window, scan host, and responsible contacts.
2. Coordinate with rail operations, network operations, and the safety or control-system owner.
3. Confirm that the scan host has the approved network path and that logging/alerting teams understand the activity.
4. Start with the smallest approved subnet and conservative concurrency and timeout values.
5. Record a stop contact and stop condition before beginning.

## During a Scan

- Scan only approved addresses and ports.
- Do not attempt credentials, authentication bypasses, exploit payloads, configuration changes, or device commands.
- Monitor controller, HMI, network, and safety alarms for unexpected behavior.
- Stop immediately if operations report instability, latency, alarms, or unexpected device behavior.

## After a Scan

- Treat a reachable service as an exposure candidate, not proof of a vulnerable or compromised asset.
- Validate findings through approved engineering and security workflows.
- Store reports according to the organization’s data-handling policy.
- Create tickets with asset owner, network location, evidence, severity rationale, and recommended remediation.

## Emergency Stop

Terminate the scanner from the console with `Ctrl+C`, notify the designated operations contact, preserve the partial report, and document the reason for stopping.
