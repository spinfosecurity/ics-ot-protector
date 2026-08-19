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

function Export-ScanReportJson {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [hashtable]$Metadata
    )

    $ordered = Sort-ScanFindings -Findings (ConvertTo-StandardFindings -Findings $Findings)
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
        Writes a timestamped JSON scan report using the shared schema.
    .OUTPUTS
        PSCustomObject with ReportPath property.
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
        [string]$Timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
    )

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $reportPath = Join-Path $OutputDir "${Prefix}-${Timestamp}.json"
    Export-ScanReportJson -Findings $Findings -Path $reportPath -Metadata $Metadata

    [pscustomobject]@{
        ReportPath = $reportPath
    }
}
