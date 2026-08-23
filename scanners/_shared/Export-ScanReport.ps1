# Unified JSON export for ICS OT Protector sector scanners.
# All scanners write schema_version 1.0 documents with metadata + findings.

function Get-SeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'CRITICAL' { return 0 }
        'HIGH'     { return 1 }
        'MEDIUM'   { return 2 }
        default    { return 3 }
    }
}

function Sort-ScanFindings {
    param([array]$Findings)
    @($Findings | Sort-Object @{ Expression = { Get-SeverityRank $_.Severity } }, Host, Port)
}

function ConvertTo-StandardFindings {
    param([array]$Findings)

    $normalized = foreach ($f in $Findings) {
        $hostValue = if ($null -ne $f.Host -and "$($f.Host)".Length -gt 0) { "$($f.Host)" }
                     elseif ($null -ne $f.IP -and "$($f.IP)".Length -gt 0) { "$($f.IP)" }
                     elseif ($null -ne $f.IpAddress -and "$($f.IpAddress)".Length -gt 0) { "$($f.IpAddress)" }
                     else { '' }

        $timestamp = if ($f.Timestamp) { "$($f.Timestamp)" } else { (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss') }
        $category = if ($f.Category) { "$($f.Category)" }
                   elseif ($f.ThreatType) { "$($f.ThreatType)" }
                   else { 'General' }
        $description = if ($f.Description) { "$($f.Description)" }
                       elseif ($f.ThreatContext) { "$($f.ThreatContext)" }
                       else { '' }
        $remediation = if ($f.Remediation) { "$($f.Remediation)" }
                       elseif ($f.Action) { "$($f.Action)" }
                       else { '' }

        [pscustomobject]@{
            Timestamp   = $timestamp
            Host        = $hostValue
            Port        = [int]$f.Port
            Service     = "$($f.Service)"
            Severity    = "$($f.Severity)"
            Category    = $category
            Description = $description
            Remediation = $remediation
        }
    }

    return ,@($normalized)
}

function Get-ScanReportSummary {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [int]$HostsScanned = 0,
        [int]$PortsChecked = 0,
        [int]$DurationMs = 0
    )

    $bySeverity = @{}
    foreach ($f in $Findings) {
        $sev = [string]$f.Severity
        if (-not $bySeverity.ContainsKey($sev)) { $bySeverity[$sev] = 0 }
        $bySeverity[$sev]++
    }

    return [ordered]@{
        hosts_scanned         = $HostsScanned
        ports_checked         = $PortsChecked
        probes_total          = $HostsScanned * $PortsChecked
        findings_total        = @($Findings).Count
        findings_by_severity  = $bySeverity
        duration_ms           = $DurationMs
    }
}

function Export-ScanReportCsv {
    param(
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][string]$CsvPath
    )

    $doc = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
    $rows = foreach ($f in @($doc.findings)) {
        [pscustomobject]@{
            Timestamp   = $f.Timestamp
            Host        = $f.Host
            Port        = $f.Port
            Service     = $f.Service
            Severity    = $f.Severity
            Category    = $f.Category
            Description = $f.Description
            Remediation = $f.Remediation
        }
    }
    $rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
}

function Export-ScanReportJson {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [hashtable]$Metadata,
        [int]$HostsScanned = 0,
        [int]$PortsChecked = 0,
        [int]$DurationMs = 0
    )

    $ordered = Sort-ScanFindings -Findings (ConvertTo-StandardFindings -Findings $Findings)
    if (-not $Metadata.summary) {
        $Metadata.summary = Get-ScanReportSummary -Findings $ordered `
            -HostsScanned $HostsScanned -PortsChecked $PortsChecked -DurationMs $DurationMs
    }

    $document = [ordered]@{
        schema_version = '1.0'
        generated_at   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        metadata       = $Metadata
        findings       = @($ordered)
    }

    $document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Export-ScanReport {
    <#
    .SYNOPSIS
        Writes timestamped JSON (and optional CSV) scan reports using the shared schema.
    .OUTPUTS
        PSCustomObject with ReportPath and optional CsvPath properties.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,
        [Parameter(Mandatory)]
        [string]$OutputDir,
        [Parameter(Mandatory)]
        [string]$Prefix,
        [Parameter(Mandatory)]
        [hashtable]$Metadata,
        [string]$Timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss'),
        [int]$HostsScanned = 0,
        [int]$PortsChecked = 0,
        [int]$DurationMs = 0,
        [switch]$ExportCsv
    )

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $reportPath = Join-Path $OutputDir "${Prefix}-${Timestamp}.json"
    Export-ScanReportJson -Findings $Findings -Path $reportPath -Metadata $Metadata `
        -HostsScanned $HostsScanned -PortsChecked $PortsChecked -DurationMs $DurationMs

    $result = [ordered]@{ ReportPath = $reportPath }
    if ($ExportCsv) {
        $csvPath = Join-Path $OutputDir "${Prefix}-${Timestamp}.csv"
        Export-ScanReportCsv -JsonPath $reportPath -CsvPath $csvPath
        $result.CsvPath = $csvPath
    }

    return [pscustomobject]$result
}
