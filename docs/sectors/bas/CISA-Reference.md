# CISA Reference - Building Automation System Cybersecurity

## Key 2026 ICS Advisories

### Honeywell IQ4x BMS Controller (ICSA-26-069-03)
- Published: March 10, 2026
- CVE-2026-3611 (CVSS 10.0 Critical)
- Web HMI ships with authentication disabled by factory default
- Common in data centers and healthcare facilities
- Allows unauthenticated attackers to create administrative accounts

### Johnson Controls C-CURE 9000 / Victor (ICSA-26-204-01)
- Published: July 23, 2026
- Remote code execution via network access
- Affects C-CURE 9000 and Victor application server v2.90-v3.0 and earlier

### Siemens Desigo CC / SENTRON Powermanager
- Published: August 2025 (ongoing relevance into 2026)
- Least-privilege violation vulnerability
- Enables privilege escalation
- Affects Desigo CC versions 5.0, 5.1, 6, 7, 8

### BACnet Protocol Vulnerabilities
- CVE-2026-24060: Unauthenticated data exposure/modification
- CVE-2026-41503: Out-of-bounds read in bacnet-stack ReadPropertyMultiple decoder (fixed in 1.4.3)
- CVE-2026-21870: Stack buffer overflow in BACnet ubasic interpreter

## CISA Recommendations for BAS/BMS Security

1. Remove BACnet/BMS devices from direct internet exposure
2. Implement VPN for all remote HVAC/BMS access
3. Segment building automation network from corporate IT network
4. Upgrade to BACnet/SC (Secure Connect) where possible
5. Verify vendor-specific authentication is enabled (especially Honeywell IQ4x)
6. Patch bacnet-stack and vendor firmware to latest versions
7. Monitor for unauthorized Who-Is/I-Am broadcast traffic

## CISA Cyber Hygiene Services

Free vulnerability scanning: https://www.cisa.gov/cyber-hygiene-services

## Reporting Incidents

- Phone: 1-844-Say-CISA (1-844-729-2472)
- Online: https://www.cisa.gov/report-cyber-incident
- FBI IC3: https://www.ic3.gov
