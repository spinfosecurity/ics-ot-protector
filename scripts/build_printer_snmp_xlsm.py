#!/usr/bin/env python3
"""
Generates PrinterConsumables.xlsm – an Excel macro-enabled workbook.

The VBA source is read from PrinterSNMP.bas (must be in the same directory).
Run once on any machine that has Python + openpyxl installed:
    python3 build_printer_snmp_xlsm.py

Then open PrinterConsumables.xlsm in Excel (Windows), enable macros,
fill in your printer IPs on the "Printers" sheet, and run the ScanPrinters macro.
"""

import shutil, os
from pathlib import Path


def build_xlsm(out_path: str = "PrinterConsumables.xlsm"):
    import openpyxl
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()

    hdr_fill = PatternFill("solid", fgColor="1F4E79")
    hdr_font = Font(bold=True, color="FFFFFF", size=11)
    thin     = Border(
        left=Side(style="thin"), right=Side(style="thin"),
        top=Side(style="thin"),  bottom=Side(style="thin"),
    )

    # ------------------------------------------------------------------ #
    #  Sheet 1: Printers
    # ------------------------------------------------------------------ #
    ws_printers = wb.active
    ws_printers.title = "Printers"

    ws_printers.merge_cells("A1:D1")
    c = ws_printers["A1"]
    c.value = "Printer List  —  Edit this sheet, then run the ScanPrinters macro"
    c.font  = Font(bold=True, size=13, color="FFFFFF")
    c.fill  = PatternFill("solid", fgColor="0D3F6E")
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws_printers.row_dimensions[1].height = 26

    for col, h in enumerate(
        ["Printer Name", "IP Address", "Community String (blank = 'public')", "Notes"], 1
    ):
        cell = ws_printers.cell(2, col, h)
        cell.font      = hdr_font
        cell.fill      = hdr_fill
        cell.border    = thin
        cell.alignment = Alignment(horizontal="center", vertical="center")
    ws_printers.row_dimensions[2].height = 18

    samples = [
        ("Office Printer 1",    "192.168.1.100", "public",  "Reception"),
        ("IT Room Xerox",       "192.168.1.101", "private", "IT Dept"),
        ("Finance Floor Canon", "192.168.1.102", "",        "Finance"),
    ]
    alt = ["D6E4F0", "FFFFFF"]
    for r, row in enumerate(samples, 3):
        fill = PatternFill("solid", fgColor=alt[r % 2])
        for col, val in enumerate(row, 1):
            cell = ws_printers.cell(r, col, val)
            cell.fill   = fill
            cell.border = thin
            cell.alignment = Alignment(vertical="center")

    ws_printers.column_dimensions["A"].width = 26
    ws_printers.column_dimensions["B"].width = 18
    ws_printers.column_dimensions["C"].width = 34
    ws_printers.column_dimensions["D"].width = 22

    # ------------------------------------------------------------------ #
    #  Sheet 2: Consumables  (macro populates this)
    # ------------------------------------------------------------------ #
    ws_results = wb.create_sheet("Consumables")
    ws_results.merge_cells("A1:J1")
    rc = ws_results["A1"]
    rc.value = "Run the ScanPrinters macro (Alt+F8) to populate this sheet"
    rc.font  = Font(bold=True, size=12, color="FFFFFF", italic=True)
    rc.fill  = PatternFill("solid", fgColor="0D3F6E")
    rc.alignment = Alignment(horizontal="center", vertical="center")
    ws_results.row_dimensions[1].height = 26

    # ------------------------------------------------------------------ #
    #  Sheet 3: Instructions
    # ------------------------------------------------------------------ #
    ws_help = wb.create_sheet("Instructions")
    rows = [
        ("HOW TO USE", True, "0D3F6E", "FFFFFF"),
        ("", False, None, None),
        ("Step 1 – Open in Excel", True, "2E75B6", "FFFFFF"),
        ("  Open PrinterConsumables.xlsm in Microsoft Excel for Windows.", False, None, None),
        ("  Click 'Enable Macros' if prompted.", False, None, None),
        ("", False, None, None),
        ("Step 2 – Import the VBA module (first time only)", True, "2E75B6", "FFFFFF"),
        ("  Press Alt+F11 to open the VBA Editor.", False, None, None),
        ("  Click File → Import File → select PrinterSNMP.bas.", False, None, None),
        ("  Close the VBA Editor (Alt+Q).", False, None, None),
        ("", False, None, None),
        ("Step 3 – Add your printers", True, "2E75B6", "FFFFFF"),
        ("  Go to the 'Printers' sheet.", False, None, None),
        ("  Replace the sample rows with your printers: Name, IP, Community.", False, None, None),
        ("  Leave Community blank to use 'public'.", False, None, None),
        ("", False, None, None),
        ("Step 4 – Run the macro", True, "2E75B6", "FFFFFF"),
        ("  Press Alt+F8 → select ScanPrinters → click Run.", False, None, None),
        ("  Results appear on the 'Consumables' sheet.", False, None, None),
        ("", False, None, None),
        ("Step 5 (optional) – Export a shareable copy", True, "2E75B6", "FFFFFF"),
        ("  Run the ExportSnapshot macro to save a plain .xlsx for sharing.", False, None, None),
        ("", False, None, None),
        ("REQUIREMENTS", True, "0D3F6E", "FFFFFF"),
        ("", False, None, None),
        ("  • Microsoft Excel for Windows (macros must be enabled).", False, None, None),
        ("  • Windows PowerShell – built into every modern Windows PC.", False, None, None),
        ("  • NO external SNMP tools required (snmpget.exe, etc.).", False, None, None),
        ("  • Printers must have SNMP v1/v2c enabled.", False, None, None),
        ("  • UDP port 161 must be reachable from this PC (check firewall/VPN).", False, None, None),
        ("", False, None, None),
        ("COLOUR LEGEND", True, "0D3F6E", "FFFFFF"),
        ("", False, None, None),
        ("  Green  bar = ≥ 26 % remaining  (OK)", False, "A9D18E", None),
        ("  Yellow bar = 11–25 % remaining (Warning)", False, "FFD966", None),
        ("  Red    bar = ≤ 10 % remaining  (Critical)", False, "FF7043", None),
        ("  Grey   bar = Level not reported by printer", False, "D9D9D9", None),
    ]

    ws_help.column_dimensions["A"].width = 80
    for r, (text, bold, bg, fg) in enumerate(rows, 1):
        cell = ws_help.cell(r, 1, text)
        cell.font = Font(bold=bold, size=11 if bold else 10,
                         color=fg if fg else "000000")
        if bg:
            cell.fill = PatternFill("solid", fgColor=bg)
        cell.alignment = Alignment(vertical="center", indent=0 if bold else 2)
        if bold:
            ws_help.row_dimensions[r].height = 22

    # ------------------------------------------------------------------ #
    #  Save skeleton as .xlsm
    # ------------------------------------------------------------------ #
    tmp = out_path.replace(".xlsm", "_tmp.xlsx")
    wb.save(tmp)
    shutil.copy(tmp, out_path)
    os.remove(tmp)
    print(f"✓  Workbook saved:   {out_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Generate PrinterConsumables.xlsm (VBA in PrinterSNMP.bas)"
    )
    parser.add_argument("--out", default="PrinterConsumables.xlsm")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    out        = script_dir / args.out
    build_xlsm(str(out))

    bas = script_dir / "PrinterSNMP.bas"
    if bas.exists():
        print(f"✓  VBA module ready: {bas}")
    else:
        print("  WARNING: PrinterSNMP.bas not found next to this script.")
