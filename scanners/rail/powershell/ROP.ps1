#Requires -Version 7.0
<#
.SYNOPSIS
    Rail-OT-Protector (ROP) PowerShell Scanner

.DESCRIPTION
    Scans rail/transit OT subnets for exposed remote-access services, ICS protocols,
    EOT/HOT remote linking risk (CVE-2025-1727), and legacy RailSafe SCADA API exposure.
    Outputs timestamped JSON and CSV reports with CRITICAL/HIGH/MEDIUM severity labels.

.PARAMETER Subnets
    One or more CIDR subnets to scan. Example: 10.10.20.0/24,10.10.30.0/24

.PARAMETER TimeoutMs
    TCP connection timeout in milliseconds. Range: 100-10000. Default: 1500.

.PARAMETER Threads
    Maximum concurrent runspace threads. Range: 1-512. Default: 64.

.PARAMETER OutputDir
    Directory for JSON and CSV report output. Default: ./reports

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

. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Import-SectorConfig.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'ScannerHelpers.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Export-ScanReport.ps1')
Initialize-RailConfig -Config (Import-SectorConfig -Sector 'rail')

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
# Port catalog
# ---------------------------------------------------------------------------
function Get-PortCatalog {
    param([switch]$FastEotHot)
    Get-RailPortCatalog -FastEotHot:$FastEotHot
}

# ---------------------------------------------------------------------------
# TCP probe (non-blocking async connect)
# ---------------------------------------------------------------------------
function Test-TcpPort {
    param([string]$TargetHost, [int]$Port, [int]$Timeout)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout, $false)) { return $false }
        $client.EndConnect($ar)
        return $true
    } catch { return $false }
    finally { $client.Dispose() }
}

# ---------------------------------------------------------------------------
# Main (skipped when $ROP_TEST_MODE is set before dot-sourcing)
# ---------------------------------------------------------------------------
if ($ROP_TEST_MODE -or $global:ROP_TEST_MODE) { return }

# Validate and resolve output directory
if (-not (Test-Path -LiteralPath $OutputDir)) {
    try {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: $OutputDir"
    } catch {
        Write-Log "Cannot create output directory '$OutputDir': $_" -Level ERROR
        exit 1
    }
}

# Build target list
$allTargets = New-Object System.Collections.Generic.List[string]
foreach ($subnet in $Subnets) {
    $subnet = $subnet.Trim()
    try {
        $ips = ConvertTo-IpRange -Cidr $subnet
        foreach ($ip in $ips) { $allTargets.Add($ip) }
        Write-Log "Resolved $($ips.Count) hosts from $subnet"
    } catch {
        Write-Log "Skipping invalid subnet '$subnet': $_" -Level WARN
    }
}

$targets = @($allTargets | Sort-Object -Unique)
if ($targets.Count -eq 0) {
    Write-Log 'No valid scan targets were generated. Check subnet input.' -Level ERROR
    exit 1
}

$portCatalog = @(Get-PortCatalog -FastEotHot:$EotHotOnly)
Write-Log "Scan starting | Targets: $($targets.Count) | Ports: $($portCatalog.Count) | Threads: $Threads | Timeout: ${TimeoutMs}ms | EotHotOnly: $($EotHotOnly.IsPresent)"

# Runspace pool setup
$pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
$pool.Open()
$jobs  = New-Object System.Collections.Generic.List[pscustomobject]

$scanScript = {
    param($TargetHost, $PortCatalog, $TimeoutMs)

    function Test-TcpPortLocal {
        param([string]$H, [int]$P, [int]$T)
        $c = [System.Net.Sockets.TcpClient]::new()
        try {
            $ar = $c.BeginConnect($H, $P, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne($T, $false)) { return $false }
            $c.EndConnect($ar); return $true
        } catch { return $false } finally { $c.Dispose() }
    }

    $hits = @()
    foreach ($entry in $PortCatalog) {
        if (Test-TcpPortLocal -H $TargetHost -P $entry.Port -T $TimeoutMs) {
            $hits += [pscustomobject]@{
                Timestamp   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                Host        = $TargetHost
                Port        = $entry.Port
                Service     = $entry.Name
                Severity    = $entry.Severity
                Category    = $entry.Category
                Description = $entry.Description
            }
        }
    }
    return $hits
}

# Queue all jobs
foreach ($target in $targets) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($scanScript).AddArgument($target).AddArgument($portCatalog).AddArgument($TimeoutMs)
    $handle = $ps.BeginInvoke()
    $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $handle; Host = $target })
}

# Collect results with progress
$done = 0
foreach ($job in $jobs) {
    $results = $job.PS.EndInvoke($job.Handle)
    foreach ($r in $results) {
        $script:Findings.Add($r)
        $color = switch ($r.Severity) { 'CRITICAL' { 'Red' } 'HIGH' { 'Yellow' } default { 'White' } }
        Write-Host ("[{0}] [{1}] {2}:{3}  {4}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $r.Severity.PadRight(8), $r.Host, $r.Port, $r.Description) -ForegroundColor $color
    }
    if ($job.PS.HadErrors) {
        foreach ($err in $job.PS.Streams.Error) { Write-Log "Runspace error on $($job.Host): $err" -Level WARN }
    }
    $job.PS.Dispose()
    $done++
    Write-Progress -Activity 'Rail-OT-Protector Scanning' `
        -Status "Hosts processed: $done / $($targets.Count)" `
        -PercentComplete ([math]::Round(($done / $targets.Count) * 100, 0))
}

$pool.Close(); $pool.Dispose()
Write-Progress -Activity 'Rail-OT-Protector Scanning' -Completed

# Write reports
$exportPaths = Export-ScanReport -Findings @($script:Findings.ToArray()) -OutputDir $OutputDir -Prefix 'ROP-results'

Write-Log "Scan complete | Findings: $($script:Findings.Count) | JSON: $($exportPaths.JsonPath) | CSV: $($exportPaths.CsvPath)"
