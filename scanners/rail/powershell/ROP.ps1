#Requires -Version 7.0
<#
.SYNOPSIS
    Rail-OT-Protector (ROP) PowerShell Scanner

.DESCRIPTION
    Scans rail/transit OT subnets for exposed remote-access services, ICS protocols,
    EOT/HOT remote linking risk (CVE-2025-1727), and legacy RailSafe SCADA API exposure.
    Outputs timestamped JSON reports with CRITICAL/HIGH/MEDIUM severity labels.

.PARAMETER Subnets
    One or more CIDR subnets to scan. Example: 10.10.20.0/24,10.10.30.0/24

.PARAMETER TimeoutMs
    TCP connection timeout in milliseconds. Range: 100-10000. Default: 1500.

.PARAMETER Threads
    Maximum concurrent runspace threads. Range: 1-512. Default: 64.

.PARAMETER OutputDir
    Directory for JSON report output. Default: ./reports

.PARAMETER EotHotOnly
    Fast-scan mode. Checks only EOT/HOT-related ports (CVE-2025-1727 indicators).

.EXAMPLE
    pwsh ./ROP.ps1 -Subnets 10.10.20.0/24 -OutputDir ./reports

.EXAMPLE
    pwsh ./ROP.ps1 -Subnets 10.10.20.0/24,10.10.30.0/24 -EotHotOnly -TimeoutMs 1200 -Threads 128

.NOTES
    Copyright (c) 2026 spinfosecurity | MIT License
    References: CISA AA26-097A, FBI PSA 2026-08-01
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Comma-separated CIDR ranges, e.g. 10.10.20.0/24')]
    [ValidateNotNullOrEmpty()]
    [string[]]$Subnets,

    [Parameter(HelpMessage = 'TCP connect timeout in milliseconds (100-10000)')]
    [ValidateRange(100, 10000)]
    [int]$TimeoutMs = 1500,

    [Parameter(HelpMessage = 'Maximum concurrent threads (1-512)')]
    [ValidateRange(1, 512)]
    [int]$Threads = 64,

    [Parameter(HelpMessage = 'Output directory for reports')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDir = './reports',

    [Parameter(HelpMessage = 'Fast mode: check EOT/HOT ports only (CVE-2025-1727)')]
    [switch]$EotHotOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SharedRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $SharedRoot '_shared' 'Import-SectorConfig.ps1')
. (Join-Path $SharedRoot '_shared' 'ScannerHelpers.ps1')
. (Join-Path $SharedRoot '_shared' 'ScanEngine.ps1')
. (Join-Path $SharedRoot '_shared' 'Export-ScanReport.ps1')
$script:SectorConfig = Import-SectorConfig -Sector 'rail'
Initialize-RailConfig -Config $script:SectorConfig

# ---------------------------------------------------------------------------
# Thread-safe findings collection
# ---------------------------------------------------------------------------
$script:Findings = [System.Collections.Concurrent.ConcurrentBag[pscustomobject]]::new()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Cyan' } }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Main (skipped when $ROP_TEST_MODE is set before dot-sourcing)
# ---------------------------------------------------------------------------
if ($ROP_TEST_MODE -or $global:ROP_TEST_MODE) { return }

if (-not (Test-Path -LiteralPath $OutputDir)) {
    try {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: $OutputDir"
    } catch {
        Write-Log "Cannot create output directory '$OutputDir': $_" -Level ERROR
        exit 1
    }
}

$targets = Build-ScanTargets -Subnets $Subnets
if ($targets.Count -eq 0) {
    Write-Log 'No valid scan targets were generated. Check subnet input.' -Level ERROR
    exit 1
}

foreach ($subnet in $Subnets) {
    $trimmed = $subnet.Trim()
    if ($trimmed) {
        Write-Log "Resolved targets from $trimmed"
    }
}

$portCatalog = Get-RailPortCatalogFromConfig -Config $script:SectorConfig -FastEotHot:$EotHotOnly
Write-Log "Scan starting | Targets: $($targets.Count) | Ports: $($portCatalog.Count) | Threads: $Threads | Timeout: ${TimeoutMs}ms | EotHotOnly: $($EotHotOnly.IsPresent)"

$null = Invoke-TcpPortScan -Targets $targets -PortCatalog $portCatalog -TimeoutMs $TimeoutMs -Threads $Threads -OnFinding {
    param($Finding)
    $script:Findings.Add($Finding)
    $color = switch ($Finding.Severity) { 'CRITICAL' { 'Red' } 'HIGH' { 'Yellow' } default { 'White' } }
    Write-Host ("[{0}] [{1}] {2}:{3}  {4}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Finding.Severity.PadRight(8), $Finding.Host, $Finding.Port, $Finding.Description) -ForegroundColor $color
} -OnProgress {
    param($TargetHost, $Processed, $Total)
    Write-Progress -Activity 'Rail-OT-Protector Scanning' `
        -Status "Hosts processed: $Processed / $Total" `
        -PercentComplete ([math]::Round(($Processed / $Total) * 100, 0))
}

Write-Progress -Activity 'Rail-OT-Protector Scanning' -Completed

$exportPaths = Export-ScanReport -Findings @($script:Findings.ToArray()) -OutputDir $OutputDir -Prefix 'ROP-results' `
    -Metadata @{
        sector       = 'rail'
        scanner      = 'Rail-OT-Protector'
        version      = '1.0.0'
        subnets      = ($Subnets -join ',')
        timeout_ms   = $TimeoutMs
        threads      = $Threads
        eot_hot_only = [bool]$EotHotOnly
        reference    = 'CISA AA26-097A, FBI PSA 2026-08-01'
    }

Write-Log "Scan complete | Findings: $($script:Findings.Count) | Report: $($exportPaths.ReportPath)"
