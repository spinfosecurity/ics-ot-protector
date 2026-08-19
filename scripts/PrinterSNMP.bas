Attribute VB_Name = "PrinterSNMP"
Option Explicit

' ============================================================
'  CONFIGURATION  – edit these defaults before your first run
' ============================================================
Const DEFAULT_COMMUNITY As String = "public"
Const SNMP_TIMEOUT_MS   As Long   = 3000    ' milliseconds per SNMP request
Const MAX_SUPPLIES       As Long   = 20      ' max supply slots to probe per printer

' ============================================================
'  RFC 3805 / Printer-MIB base OIDs  (index appended at query time)
' ============================================================
Const OID_SYS_NAME    As String = "1.3.6.1.2.1.1.5.0"
Const OID_SUPPLY_DESC As String = "1.3.6.1.2.1.43.11.1.1.6.1"
Const OID_SUPPLY_TYPE As String = "1.3.6.1.2.1.43.11.1.1.5.1"
Const OID_SUPPLY_MAX  As String = "1.3.6.1.2.1.43.11.1.1.8.1"
Const OID_SUPPLY_LVL  As String = "1.3.6.1.2.1.43.11.1.1.9.1"

' ============================================================
'  Supply-type integer -> friendly name
' ============================================================
Private Function SupplyTypeName(code As Long) As String
    Select Case code
        Case 3:  SupplyTypeName = "Toner"
        Case 4:  SupplyTypeName = "Waste Toner"
        Case 5:  SupplyTypeName = "Ink"
        Case 6:  SupplyTypeName = "Ink Cartridge"
        Case 7:  SupplyTypeName = "Ink Ribbon"
        Case 9:  SupplyTypeName = "OPC Drum"
        Case 10: SupplyTypeName = "Developer"
        Case 11: SupplyTypeName = "Fuser Oil"
        Case 15: SupplyTypeName = "Fuser"
        Case 20: SupplyTypeName = "Transfer Unit"
        Case 21: SupplyTypeName = "Toner Cartridge"
        Case 22: SupplyTypeName = "Fuser Kit"
        Case 25: SupplyTypeName = "Maintenance Kit"
        Case 26: SupplyTypeName = "Drum Kit"
        Case Else: SupplyTypeName = "Other (" & code & ")"
    End Select
End Function

' ============================================================
'  Run a PowerShell script file and return its stdout.
'  Writes the script to a temp .ps1 file to avoid any
'  command-line length limits and quoting headaches.
' ============================================================
Private Function RunPSFile(psCode As String) As String
    Dim base    As String
    base = Environ("TEMP") & "\snmp_" & Format(Timer * 1000, "0")

    Dim ps1File As String : ps1File = base & ".ps1"
    Dim outFile As String : outFile = base & ".txt"

    ' Write script
    Dim fNo As Integer
    fNo = FreeFile
    Open ps1File For Output As #fNo
    Print #fNo, psCode
    Close #fNo

    ' Execute hidden, wait for completion
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass " & _
           "-File """ & ps1File & """ > """ & outFile & """ 2>&1", 0, True

    ' Read output
    Dim result As String
    If Dir(outFile) <> "" Then
        fNo = FreeFile
        Open outFile For Input As #fNo
        Dim ln As String
        Do While Not EOF(fNo)
            Line Input #fNo, ln
            result = result & Trim(ln) & vbLf
        Loop
        Close #fNo
        Kill outFile
    End If
    If Dir(ps1File) <> "" Then Kill ps1File

    RunPSFile = Trim(result)
End Function

' ============================================================
'  Core PowerShell SNMP helper functions – emitted once into
'  every script block so each call is self-contained.
' ============================================================
Private Function PSHelperFunctions() As String
    PSHelperFunctions = _
        "function Encode-VarInt([int]$v) {" & vbLf & _
        "    if ($v -lt 128) { return [byte[]]$v }" & vbLf & _
        "    $b = [System.Collections.Generic.List[byte]]::new()" & vbLf & _
        "    do { $b.Insert(0, [byte]($v -band 0x7f)); $v = $v -shr 7 } while ($v -gt 0)" & vbLf & _
        "    $b[0] = $b[0] -bor 0x80" & vbLf & _
        "    return $b.ToArray()" & vbLf & _
        "}" & vbLf & _
        "function Encode-OID([string]$oid) {" & vbLf & _
        "    $p = $oid.Split('.')" & vbLf & _
        "    $out = [System.Collections.Generic.List[byte]]::new()" & vbLf & _
        "    $out.Add([byte]([int]$p[0] * 40 + [int]$p[1]))" & vbLf & _
        "    for ($i = 2; $i -lt $p.Length; $i++) {" & vbLf & _
        "        $out.AddRange((Encode-VarInt([int]$p[$i])))" & vbLf & _
        "    }" & vbLf & _
        "    $bytes = $out.ToArray()" & vbLf & _
        "    return [byte[]](0x06) + [byte[]]($bytes.Length) + $bytes" & vbLf & _
        "}" & vbLf & _
        "function Build-GetRequest([string]$community, [string]$oid, [int]$reqId) {" & vbLf & _
        "    $oidBytes  = Encode-OID $oid" & vbLf & _
        "    $nullBytes = [byte[]](0x05, 0x00)" & vbLf & _
        "    $varbind   = [byte[]](0x30) + [byte[]]($oidBytes.Length + $nullBytes.Length) + $oidBytes + $nullBytes" & vbLf & _
        "    $commBytes = [System.Text.Encoding]::ASCII.GetBytes($community)" & vbLf & _
        "    $commTlv   = [byte[]](0x04) + [byte[]]($commBytes.Length) + $commBytes" & vbLf & _
        "    $rid       = [byte[]](0x02, 0x04," & vbLf & _
        "                    [byte](($reqId -shr 24) -band 0xff)," & vbLf & _
        "                    [byte](($reqId -shr 16) -band 0xff)," & vbLf & _
        "                    [byte](($reqId -shr  8) -band 0xff)," & vbLf & _
        "                    [byte]( $reqId          -band 0xff))" & vbLf & _
        "    $errSt     = [byte[]](0x02, 0x01, 0x00)" & vbLf & _
        "    $errIdx    = [byte[]](0x02, 0x01, 0x00)" & vbLf & _
        "    $varList   = [byte[]](0x30) + [byte[]]($varbind.Length)  + $varbind" & vbLf & _
        "    $pdu       = [byte[]](0xa0) + [byte[]]($rid.Length + $errSt.Length + $errIdx.Length + $varList.Length) + $rid + $errSt + $errIdx + $varList" & vbLf & _
        "    $ver       = [byte[]](0x02, 0x01, 0x00)" & vbLf & _
        "    $inner     = $ver + $commTlv + $pdu" & vbLf & _
        "    return [byte[]](0x30) + [byte[]]($inner.Length) + $inner" & vbLf & _
        "}" & vbLf & _
        "function Decode-Response([byte[]]$resp) {" & vbLf & _
        "    # Locate the GetResponse PDU tag 0xa2" & vbLf & _
        "    $i = 0" & vbLf & _
        "    while ($i -lt $resp.Length -and $resp[$i] -ne 0xa2) { $i++ }" & vbLf & _
        "    if ($i -ge $resp.Length) { return '' }" & vbLf & _
        "    $i++  # skip tag" & vbLf & _
        "    # Skip length (possibly multi-byte)" & vbLf & _
        "    if ($resp[$i] -band 0x80) { $i += ($resp[$i] -band 0x7f) + 1 } else { $i++ }" & vbLf & _
        "    # Skip reqId TLV" & vbLf & _
        "    $i++; $i += $resp[$i] + 1" & vbLf & _
        "    # Skip error-status TLV" & vbLf & _
        "    $i++; $i += $resp[$i] + 1" & vbLf & _
        "    # Skip error-index TLV" & vbLf & _
        "    $i++; $i += $resp[$i] + 1" & vbLf & _
        "    # Now at VarBindList (0x30)" & vbLf & _
        "    $i++  # skip 0x30 tag" & vbLf & _
        "    if ($resp[$i] -band 0x80) { $i += ($resp[$i] -band 0x7f) + 1 } else { $i++ }" & vbLf & _
        "    # First VarBind (0x30)" & vbLf & _
        "    $i++  # skip 0x30 tag" & vbLf & _
        "    if ($resp[$i] -band 0x80) { $i += ($resp[$i] -band 0x7f) + 1 } else { $i++ }" & vbLf & _
        "    # Skip OID TLV" & vbLf & _
        "    $i++; $olen = $resp[$i]; $i++; $i += $olen" & vbLf & _
        "    # Value TLV" & vbLf & _
        "    $vtag = $resp[$i]; $i++" & vbLf & _
        "    $vlen = $resp[$i]; $i++" & vbLf & _
        "    if ($vlen -band 0x80) {" & vbLf & _
        "        $nb = $vlen -band 0x7f; $vlen = 0" & vbLf & _
        "        for ($j = 0; $j -lt $nb; $j++) { $vlen = $vlen * 256 + $resp[$i]; $i++ }" & vbLf & _
        "    }" & vbLf & _
        "    $vbytes = $resp[$i..($i + $vlen - 1)]" & vbLf & _
        "    switch ($vtag) {" & vbLf & _
        "        0x04 { return [System.Text.Encoding]::ASCII.GetString($vbytes) }  # OCTET STRING" & vbLf & _
        "        0x02 { $n = 0; foreach ($b in $vbytes) { $n = $n * 256 + $b }; return [string]$n }  # INTEGER" & vbLf & _
        "        0x43 { $n = 0; foreach ($b in $vbytes) { $n = $n * 256 + $b }; return [string]$n }  # TimeTicks" & vbLf & _
        "        0x41 { $n = 0; foreach ($b in $vbytes) { $n = $n * 256 + $b }; return [string]$n }  # Counter32" & vbLf & _
        "        0x42 { $n = 0; foreach ($b in $vbytes) { $n = $n * 256 + $b }; return [string]$n }  # Gauge32" & vbLf & _
        "        0x40 { return ($vbytes | ForEach-Object { $_.ToString() }) -join '.' }              # IpAddress" & vbLf & _
        "        default { return '' }" & vbLf & _
        "    }" & vbLf & _
        "}" & vbLf & _
        "function SNMP-Get([string]$ip, [string]$community, [string]$oid, [int]$timeoutMs) {" & vbLf & _
        "    $msg = Build-GetRequest $community $oid 1" & vbLf & _
        "    $udp = New-Object System.Net.Sockets.UdpClient" & vbLf & _
        "    $udp.Client.ReceiveTimeout = $timeoutMs" & vbLf & _
        "    try {" & vbLf & _
        "        [void]$udp.Send($msg, $msg.Length, $ip, 161)" & vbLf & _
        "        $ep   = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)" & vbLf & _
        "        $resp = $udp.Receive([ref]$ep)" & vbLf & _
        "        return Decode-Response $resp" & vbLf & _
        "    } catch { return '' } finally { $udp.Close() }" & vbLf & _
        "}" & vbLf
End Function

' ============================================================
'  Query a single SNMP OID.  Returns "" on timeout/error.
'  Uses pure PowerShell UDP – no external tools needed.
' ============================================================
Private Function SNMPGet(ip As String, community As String, oid As String) As String
    Dim script As String
    script = PSHelperFunctions() & vbLf & _
             "SNMP-Get '" & ip & "' '" & community & "' '" & oid & "' " & SNMP_TIMEOUT_MS
    SNMPGet = RunPSFile(script)
End Function

' ============================================================
'  Query all four supply tables in ONE PowerShell script call.
'  Returns a pipe-delimited string:
'    desc1|type1|max1|lvl1||desc2|type2|max2|lvl2||...
'  where each supply slot is separated by "||".
' ============================================================
Private Function SNMPGetAllSupplies(ip As String, community As String) As String
    Dim n As Long
    n = MAX_SUPPLIES

    Dim script As String
    script = PSHelperFunctions() & vbLf & _
        "$ip   = '" & ip & "'" & vbLf & _
        "$comm = '" & community & "'" & vbLf & _
        "$to   = " & SNMP_TIMEOUT_MS & vbLf & _
        "$n    = " & n & vbLf & _
        "" & vbLf & _
        "# Base OIDs (without trailing index)" & vbLf & _
        "$baseDesc = '1.3.6.1.2.1.43.11.1.1.6.1'" & vbLf & _
        "$baseType = '1.3.6.1.2.1.43.11.1.1.5.1'" & vbLf & _
        "$baseMax  = '1.3.6.1.2.1.43.11.1.1.8.1'" & vbLf & _
        "$baseLvl  = '1.3.6.1.2.1.43.11.1.1.9.1'" & vbLf & _
        "" & vbLf & _
        "$results = @()" & vbLf & _
        "for ($i = 1; $i -le $n; $i++) {" & vbLf & _
        "    $desc = SNMP-Get $ip $comm ($baseDesc + '.' + $i) $to" & vbLf & _
        "    if ($desc -eq '' -or $desc -match 'noSuch|error') { continue }" & vbLf & _
        "    $type = SNMP-Get $ip $comm ($baseType + '.' + $i) $to" & vbLf & _
        "    $max  = SNMP-Get $ip $comm ($baseMax  + '.' + $i) $to" & vbLf & _
        "    $lvl  = SNMP-Get $ip $comm ($baseLvl  + '.' + $i) $to" & vbLf & _
        "    $results += ($desc + '|' + $type + '|' + $max + '|' + $lvl)" & vbLf & _
        "}" & vbLf & _
        "$results -join '||'"

    SNMPGetAllSupplies = RunPSFile(script)
End Function

' ============================================================
'  Colour helper: RGB long for a percentage
' ============================================================
Private Function PctColour(pct As Double) As Long
    If pct <= 10 Then
        PctColour = RGB(255, 112, 67)   ' red-orange  (critical)
    ElseIf pct <= 25 Then
        PctColour = RGB(255, 217, 102)  ' amber       (warning)
    Else
        PctColour = RGB(169, 209, 142)  ' green       (OK)
    End If
End Function

' ============================================================
'  Draw a simple in-cell progress bar using block characters
' ============================================================
Private Sub DrawBar(cell As Range, pct As Double)
    Dim filled As Long
    filled = CLng(pct / 5)   ' 20 segments = 100 %
    If filled > 20 Then filled = 20
    cell.Value = String(filled, Chr(9608)) & String(20 - filled, Chr(9617))
    cell.Interior.Color = PctColour(pct)
    cell.Font.Color = RGB(50, 50, 50)
    cell.Font.Name = "Courier New"
End Sub

' ============================================================
'  Helper: apply thin border to columns 1-10 in a row
' ============================================================
Private Sub ApplyRowBorder(ws As Worksheet, r As Long)
    Dim c As Long
    For c = 1 To 10
        With ws.Cells(r, c).Borders
            .LineStyle = xlContinuous
            .Weight = xlThin
        End With
    Next c
End Sub

' ============================================================
'  Helper: merge & centre a single column across a row range
' ============================================================
Private Sub MergeCenterCol(ws As Worksheet, r1 As Long, r2 As Long, c As Long)
    With ws.Range(ws.Cells(r1, c), ws.Cells(r2, c))
        .Merge
        .HorizontalAlignment = xlCenter
        .VerticalAlignment = xlCenter
    End With
End Sub

' ============================================================
'  MAIN ENTRY POINT
'  Reads printer list from "Printers" sheet, queries each via
'  pure-PowerShell SNMP (no external tools), writes results to
'  the "Consumables" sheet.
' ============================================================
Public Sub ScanPrinters()
    Application.ScreenUpdating = False
    Application.Calculation = xlCalculationManual
    Application.StatusBar = "Scanning printers via SNMP (PowerShell UDP)..."

    ' ---- ensure required sheets exist ----
    Dim wsPrinters As Worksheet, wsResults As Worksheet
    On Error Resume Next
    Set wsPrinters = ThisWorkbook.Sheets("Printers")
    Set wsResults  = ThisWorkbook.Sheets("Consumables")
    On Error GoTo 0

    If wsPrinters Is Nothing Then
        MsgBox "Sheet 'Printers' not found." & vbLf & _
               "Please create it with columns: Name | IP | Community", _
               vbCritical, "Missing Sheet"
        GoTo Cleanup
    End If

    If wsResults Is Nothing Then
        Set wsResults = ThisWorkbook.Sheets.Add( _
            After:=ThisWorkbook.Sheets(ThisWorkbook.Sheets.Count))
        wsResults.Name = "Consumables"
    End If

    ' ---- clear results sheet ----
    wsResults.Cells.Clear
    wsResults.Cells.Interior.ColorIndex = xlNone

    ' ---- title row ----
    Dim ts As String
    ts = "Printer Consumables Report  —  " & Format(Now, "yyyy-mm-dd hh:mm:ss")
    With wsResults.Range("A1:J1")
        .Merge
        .Value = ts
        .Font.Bold = True
        .Font.Size = 13
        .Font.Color = RGB(255, 255, 255)
        .Interior.Color = RGB(13, 63, 110)
        .HorizontalAlignment = xlCenter
        .RowHeight = 26
    End With

    ' ---- column headers ----
    Dim headers As Variant
    headers = Array("Printer Name", "IP Address", "Status", "Supply", _
                    "Type", "Current", "Maximum", "% Left", "Bar Chart", "Polled At")
    Dim col As Long
    For col = 0 To UBound(headers)
        With wsResults.Cells(2, col + 1)
            .Value = headers(col)
            .Font.Bold = True
            .Font.Color = RGB(255, 255, 255)
            .Interior.Color = RGB(31, 78, 121)
            .HorizontalAlignment = xlCenter
            .Borders.LineStyle = xlContinuous
        End With
    Next col
    wsResults.Rows(2).RowHeight = 18

    ' ---- iterate printers ----
    Dim resultRow  As Long : resultRow  = 3
    Dim printerRow As Long : printerRow = 2   ' row 1 is header on Printers sheet

    Do While wsPrinters.Cells(printerRow, 1).Value <> ""

        Dim pName      As String
        Dim pIP        As String
        Dim pCommunity As String
        pName      = Trim(wsPrinters.Cells(printerRow, 1).Value)
        pIP        = Trim(wsPrinters.Cells(printerRow, 2).Value)
        pCommunity = Trim(wsPrinters.Cells(printerRow, 3).Value)
        If pCommunity = "" Then pCommunity = DEFAULT_COMMUNITY

        Application.StatusBar = "Querying " & pName & " (" & pIP & ") ..."

        Dim polledAt As String
        polledAt = Format(Now, "hh:mm:ss")

        ' ---- reachability check via sysName GET ----
        Dim sysName As String
        sysName = SNMPGet(pIP, pCommunity, OID_SYS_NAME)

        If sysName = "" Then
            ' ---- unreachable ----
            With wsResults.Cells(resultRow, 1)
                .Value = pName
                .Interior.Color = RGB(255, 200, 200)
            End With
            wsResults.Cells(resultRow, 2).Value = pIP
            With wsResults.Cells(resultRow, 3)
                .Value = "UNREACHABLE"
                .Font.Color = RGB(200, 0, 0)
                .Font.Bold = True
            End With
            wsResults.Cells(resultRow, 10).Value = polledAt
            ApplyRowBorder wsResults, resultRow
            resultRow = resultRow + 1

        Else
            ' ---- query all supplies in one PS call ----
            Dim rawSupplies As String
            rawSupplies = SNMPGetAllSupplies(pIP, pCommunity)

            Dim startRow As Long
            startRow = resultRow

            Dim foundAny As Boolean
            foundAny = False

            If rawSupplies <> "" Then
                Dim supplySlots() As String
                supplySlots = Split(rawSupplies, "||")

                Dim s As Long
                For s = 0 To UBound(supplySlots)
                    Dim slotStr As String
                    slotStr = Trim(supplySlots(s))
                    If slotStr = "" Then GoTo NextSlot

                    Dim parts() As String
                    parts = Split(slotStr, "|")
                    If UBound(parts) < 3 Then GoTo NextSlot

                    Dim supDesc As String : supDesc = Trim(parts(0))
                    Dim supType As Long   : supType  = Val(Trim(parts(1)))
                    Dim supMax  As Long   : supMax   = Val(Trim(parts(2)))
                    Dim supLvl  As Long   : supLvl   = Val(Trim(parts(3)))

                    If supDesc = "" Then GoTo NextSlot
                    foundAny = True

                    Dim pct    As Double
                    Dim pctStr As String
                    If supMax > 0 And supLvl >= 0 Then
                        pct    = supLvl / supMax * 100
                        pctStr = Format(pct, "0.0") & "%"
                    ElseIf supLvl = -2 Or supMax <= 0 Then
                        pct    = -1
                        pctStr = "N/A"
                    Else
                        pct    = 0
                        pctStr = "0.0%"
                    End If

                    Dim altColour As Long
                    altColour = IIf(resultRow Mod 2 = 0, RGB(214, 228, 240), RGB(255, 255, 255))

                    ' Printer name/IP/status only on the first supply row
                    If Not foundAny Or resultRow = startRow Then
                        wsResults.Cells(resultRow, 1).Value = pName
                        wsResults.Cells(resultRow, 2).Value = pIP
                        With wsResults.Cells(resultRow, 3)
                            .Value = "Online"
                            .Font.Color = RGB(0, 128, 0)
                            .Font.Bold = True
                        End With
                    End If

                    wsResults.Cells(resultRow, 4).Value = supDesc
                    wsResults.Cells(resultRow, 5).Value = SupplyTypeName(supType)
                    wsResults.Cells(resultRow, 6).Value = IIf(supLvl >= 0, supLvl, "N/A")
                    wsResults.Cells(resultRow, 7).Value = IIf(supMax > 0, supMax, "N/A")
                    wsResults.Cells(resultRow, 8).Value = pctStr

                    If pct >= 0 Then
                        DrawBar wsResults.Cells(resultRow, 9), pct
                    Else
                        wsResults.Cells(resultRow, 9).Value = "Unknown"
                        wsResults.Cells(resultRow, 9).Interior.Color = RGB(217, 217, 217)
                    End If

                    wsResults.Cells(resultRow, 10).Value = polledAt

                    ' Background stripe on info columns
                    Dim c2 As Long
                    For c2 = 1 To 8
                        If wsResults.Cells(resultRow, c2).Interior.ColorIndex = xlNone Then
                            wsResults.Cells(resultRow, c2).Interior.Color = altColour
                        End If
                    Next c2

                    ApplyRowBorder wsResults, resultRow
                    resultRow = resultRow + 1
NextSlot:
                Next s
            End If

            If Not foundAny Then
                wsResults.Cells(resultRow, 1).Value = pName
                wsResults.Cells(resultRow, 2).Value = pIP
                wsResults.Cells(resultRow, 3).Value = "Online"
                wsResults.Cells(resultRow, 4).Value = "(No Printer-MIB supplies reported)"
                wsResults.Cells(resultRow, 10).Value = polledAt
                ApplyRowBorder wsResults, resultRow
                resultRow = resultRow + 1
            ElseIf resultRow - startRow > 1 Then
                ' Merge name/IP/status cells across supply rows
                MergeCenterCol wsResults, startRow, resultRow - 1, 1
                MergeCenterCol wsResults, startRow, resultRow - 1, 2
                MergeCenterCol wsResults, startRow, resultRow - 1, 3
            End If
        End If

        printerRow = printerRow + 1
    Loop

    ' ---- column widths & freeze ----
    With wsResults
        .Columns(1).ColumnWidth = 24
        .Columns(2).ColumnWidth = 16
        .Columns(3).ColumnWidth = 13
        .Columns(4).ColumnWidth = 36
        .Columns(5).ColumnWidth = 18
        .Columns(6).ColumnWidth = 10
        .Columns(7).ColumnWidth = 10
        .Columns(8).ColumnWidth = 10
        .Columns(9).ColumnWidth = 24
        .Columns(10).ColumnWidth = 10
        .Rows(1).RowHeight = 26
        .Activate
        .Cells(3, 1).Select
    End With
    ActiveWindow.FreezePanes = False
    ActiveWindow.FreezePanes = True

    MsgBox "Scan complete! Results are on the 'Consumables' sheet.", _
           vbInformation, "Done"

Cleanup:
    Application.ScreenUpdating = True
    Application.Calculation = xlCalculationAutomatic
    Application.StatusBar = False
End Sub

' ============================================================
'  Export Consumables sheet to a shareable .xlsx snapshot
' ============================================================
Public Sub ExportSnapshot()
    Dim savePath As String
    savePath = Application.GetSaveAsFilename( _
        InitialFileName:="PrinterReport_" & Format(Now, "yyyymmdd_hhmmss") & ".xlsx", _
        FileFilter:="Excel Workbook (*.xlsx), *.xlsx", _
        Title:="Save snapshot as...")
    If savePath = "False" Then Exit Sub

    ThisWorkbook.Sheets("Consumables").Copy
    ActiveWorkbook.SaveAs Filename:=savePath, FileFormat:=xlOpenXMLWorkbook
    ActiveWorkbook.Close False
    MsgBox "Snapshot saved: " & savePath, vbInformation, "Exported"
End Sub
