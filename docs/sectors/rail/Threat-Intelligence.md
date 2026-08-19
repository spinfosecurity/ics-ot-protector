# Threat Intelligence Notes

This document provides background on the specific threat areas covered by Rail-OT-Protector (ROP) and links findings to actionable remediation references.

---

## CVE-2025-1727 — EOT/HOT Remote Linking Protocol Weak Authentication

**CVSS v3:** 8.1 (High) | **CVSS v4:** 7.2 (High)

End-of-Train (EOT) and Head-of-Train (HOT) devices communicate over a proprietary remote linking protocol to exchange train integrity and brake pipe pressure data. CVE-2025-1727 describes weak or absent authentication in this protocol, allowing an attacker with network access to the OT subnet to inject commands, replay sessions, or disrupt EOT/HOT communication.

### Affected products

| Vendor | Product Family |
|---|---|
| Wabtec | TrainLink NG |
| Wabtec | TrainLink NG3 |
| Wabtec | TrainLink NG4 |
| Wabtec | TrainLink NG5 |
| Siemens | Trainguard EOT/HOT |
| DPS Electronics | EOT/HOT devices |

### ROP detection

ROP flags TCP connectivity to ports 4510 and 4511 on OT subnets as CRITICAL-severity EOT/HOT exposure candidates. Network reachability to these ports does not confirm exploitation but indicates an attack surface that should be investigated and isolated.

### Remediation guidance

- Apply vendor patches when available.
- Restrict EOT/HOT communication to isolated RF or physically separate OT segments.
- Monitor for unexpected TCP sessions to ports 4510/4511.
- Engage Wabtec, Siemens, or DPS Electronics product security teams for device-specific guidance.

---

## RailSafe Control Interface — Legacy SCADA API

**Age:** 13 years unpatched | **Affected versions:** 1.0, 1.1, 2.0

The RailSafe Control Interface exposes a SCADA management API that was originally designed for physically isolated rail control environments. In versions 1.0 through 2.0, the API does not implement replay protection or strong session authentication, making it vulnerable to man-in-the-middle (MitM) and replay attacks from any host that can reach the service network.

### ROP detection

ROP flags TCP port 28784 as a HIGH-severity RailSafe indicator. Operators should validate whether the service is the RailSafe API and, if so, apply network isolation immediately.

### Remediation guidance

- Isolate port 28784 from all non-authorized hosts at the firewall.
- Work with the RailSafe vendor for a patched API version.
- Log all access to the control interface and alert on anomalous activity.

---

## VNC Exploitation — FBI PSA 2026-08-01

The FBI issued PSA 2026-08-01 describing active exploitation of VNC services (TCP 5900/5901) exposed on OT and industrial networks. Attackers are observed using unauthenticated or weakly authenticated VNC sessions to gain HMI access and manipulate control system setpoints.

### Remediation guidance

- Disable VNC on all OT hosts where it is not operationally required.
- Where VNC is required, restrict access to specific jump host IPs at the firewall.
- Require authenticated VPN tunnels for any remote desktop access to OT environments.

---

## Iranian-Affiliated PLC Targeting — CISA AA26-097A

CISA AA26-097A describes Iranian-affiliated threat actor activity targeting internet-exposed and poorly segmented PLCs, HMIs, and engineering workstations in critical infrastructure sectors including transportation. See [CISA-Reference.md](./CISA-Reference.md) for the full ROP severity mapping and recommended immediate actions.

---

## Remote Access Exposure — General Guidance

| Service | Port | Risk |
|---|---|---|
| FTP | 21 | Plaintext credentials; no place in OT |
| SSH | 22 | Acceptable with key auth + ACLs; review regularly |
| Telnet | 23 | Plaintext; eliminate from all OT zones |
| HTTP | 80 | Management surface; require HTTPS + ACLs |
| HTTPS | 443 | Acceptable with valid cert + ACLs + MFA |
| RDP | 3389 | High-value target; VPN + MFA required |
| VNC | 5900/5901 | Eliminate or VPN-gate per FBI PSA 2026-08-01 |

---

## ICS Protocol Exposure — General Guidance

ICS protocols such as Modbus, EtherNet/IP, IEC 60870-5-104, DNP3, and S7 carry no native authentication in most deployments. Reachability from enterprise or external networks represents a direct risk to process integrity. Firewalls, unidirectional gateways, and strict OT zone segmentation are the primary controls.
