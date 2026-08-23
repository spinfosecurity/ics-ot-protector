#Requires -Version 5.1
<#
.SYNOPSIS
    Non-interactive sector scan runner for ICS OT Protector (PowerShell).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('water', 'energy-grid', 'bas', 'rail')]
    [string]$Sector,

    [Parameter(Mandatory)]
    [string[]]$Subnets,

    [ValidateRange(1, 512)]
    [int]$Threads = 64,

    [ValidateRange(100, 10000)]
    [int]$TimeoutMs = 1500,

    [string]$OutputDir = './reports',

    [switch]$CveOnly,
    [switch]$EotHotOnly,
    [switch]$Force,
    [switch]$NoCsv,

    [string]$Config,

    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SharedRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $SharedRoot '_shared' 'Import-SectorConfig.ps1')
. (Join-Path $SharedRoot '_shared' 'ScannerHelpers.ps1')
. (Join-Path $SharedRoot '_shared' 'Preflight.ps1')
. (Join-Path $SharedRoot '_shared' 'ScanEngine.ps1')
. (Join-Path $SharedRoot '_shared' 'Export-ScanReport.ps1')

$scope = Confirm-ScanScope -Subnets $Subnets -Force:$Force
$config = Import-SectorConfig -Sector $Sector -ConfigOverlay:$Config
$findings = [System.Collections.Concurrent.ConcurrentBag[pscustomobject]]::new()
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$progressStart = Get-Date

switch ($Sector) {
    'water' {
        $portCatalog = Get-WaterPortCatalogFromConfig -Config $config
        $reportPrefix = 'WUP-results'
        $scannerName = 'WUP WUP'
    }
    'energy-grid' {
        Initialize-EnergyGridConfig -Config $config
        $portCatalog = Get-EnergyGridPortCatalogFromConfig -Config $config -CveOnly:$CveOnly
        $reportPrefix = 'EGP-results'
        $scannerName = 'Energy Grid Protector'
    }
    'bas' {
        Initialize-BasConfig -Config $config
        $portCatalog = Get-BasPortCatalogFromConfig -Config $config
        $reportPrefix = 'BAS-results'
        $scannerName = 'BAS Guardian'
    }
    'rail' {
        $portCatalog = Get-RailPortCatalogFromConfig -Config $config -FastEotHot:$EotHotOnly
        $reportPrefix = 'ROP-results'
        $scannerName = 'Rail-OT-Protector'
    }
}

$targets = Build-ScanTargets -Subnets $scope.ValidatedSubnets
if ($targets.Count -eq 0) {
    throw 'No valid targets from -Subnets'
}

Write-PreflightSummary -Sector $Sector -HostCount $targets.Count -PortCount $portCatalog.Count `
    -Threads $Threads -TimeoutMs $TimeoutMs

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host ("[{0}] [INFO] Scan starting | Sector: {1} | Targets: {2} | Ports: {3} | Threads: {4} | Timeout: {5}ms" -f `
    (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Sector, $targets.Count, $portCatalog.Count, $Threads, $TimeoutMs)

$scanParams = @{
    Targets     = $targets
    PortCatalog = $portCatalog
    TimeoutMs   = $TimeoutMs
    Threads     = $Threads
    OnFinding   = {
        param($Finding)
        $findings.Add($Finding)
        $color = switch ($Finding.Severity) { 'CRITICAL' { 'Red' } 'HIGH' { 'Yellow' } default { 'White' } }
        Write-Host ("[{0}] [{1}] {2}:{3}  {4}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Finding.Severity, $Finding.Host, $Finding.Port, $Finding.Description) -ForegroundColor $color
    }
}
if (-not $Quiet) {
    $scanParams['OnProgress'] = {
        param($TargetHost, $Processed, $Total)
        Write-ScanEngineProgress -TargetHost $TargetHost -Processed $Processed -Total $Total -StartTime $progressStart
    }
}
$null = Invoke-TcpPortScan @scanParams

$stopwatch.Stop()

$export = Export-ScanReport -Findings @($findings.ToArray()) -OutputDir $OutputDir -Prefix $reportPrefix `
    -Metadata @{
        sector       = $Sector
        scanner      = $scannerName
        target       = ($Subnets -join ',')
        timeout_ms   = $TimeoutMs
        threads      = $Threads
        cve_only     = [bool]$CveOnly
        eot_hot_only = [bool]$EotHotOnly
        config_overlay = $(if ($Config) { $Config } else { '' })
    } `
    -HostsScanned $targets.Count -PortsChecked $portCatalog.Count -DurationMs $stopwatch.ElapsedMilliseconds `
    -ExportCsv:(-not $NoCsv)

if ($export.CsvPath) {
    Write-Host ("[{0}] [INFO] Scan complete | Findings: {1} | JSON: {2} | CSV: {3}" -f `
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $findings.Count, $export.ReportPath, $export.CsvPath)
} else {
    Write-Host ("[{0}] [INFO] Scan complete | Findings: {1} | Report: {2}" -f `
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $findings.Count, $export.ReportPath)
}
