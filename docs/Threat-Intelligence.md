# Threat Intelligence - Water Sector Attacks

## July 2026 Water Sector Attacks

Over 30 water utilities in Minnesota were hit by coordinated cyberattacks in July 2026.

### Primary Attack Vectors
1. RDP (Port 3389) - 70% of breaches
2. VNC (Port 5900) - Active exploitation by Iran-linked groups
3. SSH (Port 22) - CISA-flagged

### Targeted Vendors
- Rockwell: 4,148 exposed hosts (71% US) - MicroLogix 1400, CompactLogix
- Siemens: 4,117 exposed hosts (86% Europe) - S7-1200
- Schneider: 2,072 exposed hosts - Modicon M241/M251/M258 (CVSS 9.3)

### OT Protocols Exploited
- EtherNet/IP (44818, 2222)
- Modbus TCP (502)
- DNP3 (20000)
- S7 Comm (102)

### Mitigation Strategies
1. Disconnect exposed devices from internet
2. Implement VPN for all remote access
3. Change all default passwords
4. Enable MFA on all accounts
5. Segment IT and OT networks
