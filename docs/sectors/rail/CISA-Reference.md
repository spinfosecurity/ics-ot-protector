# CISA Reference — AA26-097A

This document summarizes the defensive context from **CISA Alert AA26-097A** (*Iranian-affiliated threat actors targeting programmable logic controllers in critical infrastructure*) as it applies to rail and transit OT environments and to Rail-OT-Protector (ROP) scan findings.

---

## Background

CISA Alert AA26-097A describes active targeting of internet-exposed and poorly segmented operational technology environments by Iranian-affiliated threat actors. Priority targets include programmable logic controllers (PLCs), human-machine interfaces (HMIs), and engineering workstations reachable via remote-access pathways such as RDP, VNC, and web management interfaces.

Rail and transit OT shares many of the attack surface characteristics described in AA26-097A, including legacy SCADA systems, flat operational networks, and aging remote-access tools.

---

## ROP Severity Mapping to AA26-097A Guidance

| ROP Severity | Service / Protocol | AA26-097A Guidance Applied |
|---|---|---|
| **CRITICAL** | EOT/HOT remote linking (CVE-2025-1727) | Isolate, audit, and patch; treat as active risk pending vendor confirmation |
| **HIGH** | RDP (3389) | Remove public exposure; require VPN and MFA per CISA guidance |
| **HIGH** | VNC (5900/5901) | Disable or remove; restrict to approved jump host paths only |
| **HIGH** | Telnet (23), FTP (21) | Eliminate from OT zones; replace with authenticated encrypted alternatives |
| **HIGH** | ICS protocols (Modbus, EtherNet/IP, IEC 60870-5-104, DNP3, S7) | Validate segmentation; block cross-zone traversal at firewall |
| **HIGH** | RailSafe Control Interface | Inventory and escalate to vendor; apply network isolation while awaiting patch |
| **MEDIUM** | SSH (22), HTTP (80), HTTPS (443) | Review access policy; enforce MFA, ACLs, and encrypted transport |

---

## Recommended Immediate Actions

1. **Inventory** all OT assets reachable via RDP, VNC, or web management interfaces.
2. **Segment** ICS protocol traffic — Modbus, DNP3, EtherNet/IP, and IEC 60870-5-104 should not be reachable from enterprise or external networks.
3. **Disable or firewall** Telnet and FTP in all OT zones immediately.
4. **Apply MFA** to all surviving remote-access pathways.
5. **Review logging and alerting** on HMI and engineering workstation access.
6. **Coordinate with vendors** for EOT/HOT firmware and RailSafe interface patches.

---

## Analyst Note

In rail and transit environments, remediation sequencing is as important as the technical fix. Changes to safety-critical OT systems — including signaling, interlocking, and train control — must be coordinated with rail operations engineering teams and validated through approved change management processes before implementation.

**Do not make live OT changes solely on the basis of scanner output without engineering review.**
