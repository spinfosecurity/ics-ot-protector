# Threat Model — Water & Wastewater

> Shared baseline: [ICS OT Protector threat model](../../threat-model.md)

## Sector Objective

Identify exposed remote access (RDP, VNC, SSH) and water-sector OT protocols (Modbus, EtherNet/IP, S7, DNP3) on authorized /24 subnets.

## Sector-Specific Considerations

- PLCs and HMIs at lift stations, treatment plants, and remote sites are primary targets per CISA AA26-097A.
- Cellular modem and out-of-band management paths are a common blind spot — this scanner checks TCP reachability only.
- Interactive wizard flow supports multi-subnet scans with optional JSON export to `~/WaterUtilitySecurity/Reports/`.
