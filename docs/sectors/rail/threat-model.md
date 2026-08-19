# Threat Model

## Security Objective

Rail-OT-Protector helps authorized defenders identify reachable remote-access services and industrial protocol ports in rail and transit OT/SCADA environments. Its output supports asset review, segmentation validation, and remediation prioritization.

## In Scope

- TCP reachability checks for configured targets and ports.
- Detection logic that identifies exposure candidates from approved scans.
- Local generation of JSON and CSV reports.

## Out of Scope

- Exploitation, credential testing, password guessing, authentication bypass, or command execution.
- Proof that a reachable port belongs to a specific device, firmware version, or vulnerable product.
- Malware detection, intrusion attribution, compliance certification, or continuous monitoring.

## Assumptions and Risks

- Firewalls, routing, NAT, and host controls can create false positives and false negatives.
- Some OT environments are sensitive to connection attempts; authorization and operational coordination are mandatory.
- Reports may reveal IP addresses, service exposure, and infrastructure details. Protect them as sensitive operational data.

## Interpretation

A finding means the scan host could reach a service at the recorded address and port under the conditions of that scan. Validate ownership, device type, business context, compensating controls, and actual vulnerability status before taking operational action.
