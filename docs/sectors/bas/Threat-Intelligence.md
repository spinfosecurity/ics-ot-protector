# Threat Intelligence - Building Automation System Attacks

## Attack Surface Overview

Building Automation Systems combine legacy industrial protocols (BACnet, LonWorks) with modern IP networking, creating a unique attack surface where:

- Authentication is often optional or disabled by default
- Encryption is frequently absent (especially in legacy BACnet/IP)
- Systems are often internet-facing for remote facility management
- Multiple vendors' equipment often coexists on the same network segment

## Vendor-Specific Risk Profiles

### Honeywell IQ4x (CVE-2026-3611)
The most severe 2026 BAS vulnerability discovered to date. IQ4x controllers used in data centers and healthcare facilities ship with web-based HMI authentication disabled by factory default, allowing any network-adjacent attacker to create administrative accounts and achieve full remote control.

### Johnson Controls C-CURE 9000 / Victor (ICSA-26-204-01)
Access control and video management platform vulnerable to remote code execution via network access. Widely deployed in commercial and government facilities.

### Siemens Desigo CC / SENTRON Powermanager
Building management and power monitoring platform affected by a least-privilege violation allowing privilege escalation, impacting the broader critical manufacturing sector.

### BACnet Protocol (Vendor-Agnostic)
BACnet's foundational design lacks native authentication and encryption. CVE-2026-24060 demonstrates that basic packet capture tools like Wireshark can expose and potentially manipulate BACnet service data without any credentials.

## Mitigation Priorities

1. Inventory all BAS/BMS devices and identify vendor/firmware versions
2. Remove all BACnet, LonWorks, and BMS web interfaces from direct internet exposure
3. Segment BAS network from corporate IT and guest networks
4. Enable authentication on all vendor platforms (verify Honeywell IQ4x specifically)
5. Apply vendor patches as they are released
6. Migrate to BACnet/SC where hardware supports it
7. Implement continuous monitoring for anomalous BACnet broadcast traffic

## References
- CISA ICS Advisories (ongoing 2026 releases)
- CVE-2026-3611, CVE-2026-24060, CVE-2026-41503
- Johnson Controls Product Security Advisories
- BACS-FUZZ Research (BACnet/SC fuzzing)
