# Threat Model

## Objective
Identify reachable remote-access services and building-automation protocol ports from an authorized scan host.

## In scope
TCP reachability checks, exposure-candidate detection, and local JSON/CSV reporting.

## Out of scope
Exploitation, credential testing, authentication bypass, command execution, proof of device identity or vulnerability, compliance certification, and attribution.

Firewalls, routing, NAT, and host controls can create false positives or negatives. BAS connection attempts can be operationally sensitive. A finding only means the scan host reached the recorded address and port; validate owner, device, controls, and vulnerability status before action.
