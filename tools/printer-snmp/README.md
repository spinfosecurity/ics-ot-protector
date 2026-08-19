# Printer SNMP Consumables Monitor

Unrelated to ICS/OT scanning — an Excel macro workbook that polls office printers via SNMP and reports toner/ink/drum levels.

## Files

- `PrinterSNMP.bas` — VBA SNMP polling logic
- `build_printer_snmp_xlsm.py` — Python script to build the `.xlsm` workbook
- `PrinterConsumables.xlsm` — Generated macro workbook
- `printers.example.json` — Example printer configuration

## Build

```bash
python3 build_printer_snmp_xlsm.py
```
