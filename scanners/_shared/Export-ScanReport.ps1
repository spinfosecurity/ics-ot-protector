# Unified JSON/CSV export for ICS OT Protector sector scanners.

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

function Export-ScanReportJson {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,
        [Parameter(Mandatory)]
        [string]$Path,
        [hashtable]$Metadata = @{}
    )

    $ordered = Sort-ScanFindings -Findings $Findings
    if ($Metadata.Count -gt 0) {
        $wrapper = [ordered]@{
            schema_version = '1.0'
            generated_at   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
            metadata       = $Metadata
            findings       = @($ordered)
        }
        $wrapper | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
    } else {
        $ordered | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

function Export-ScanReportCsv {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,
        [Parameter(Mandatory)]
        [string]$Path
    )

    $ordered = Sort-ScanFindings -Findings $Findings
    $ordered | Select-Object Timestamp, Host, Port, Service, Severity, Category, Description, Remediation |
        Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Export-ScanReport {
    <#
    .SYNOPSIS
        Writes timestamped JSON and CSV reports from a findings array.
    .OUTPUTS
        PSCustomObject with JsonPath and CsvPath properties.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,
        [Parameter(Mandatory)]
        [string]$OutputDir,
        [Parameter(Mandatory)]
        [string]$Prefix,
        [string]$Timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss'),
        [hashtable]$Metadata = @{}
    )

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $jsonPath = Join-Path $OutputDir "${Prefix}-${Timestamp}.json"
    $csvPath  = Join-Path $OutputDir "${Prefix}-${Timestamp}.csv"

    Export-ScanReportJson -Findings $Findings -Path $jsonPath -Metadata $Metadata
    Export-ScanReportCsv  -Findings $Findings -Path $csvPath

    [pscustomobject]@{
        JsonPath = $jsonPath
        CsvPath  = $csvPath
    }
}
