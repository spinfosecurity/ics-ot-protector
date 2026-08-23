<#
.SYNOPSIS
    Energy Grid Protector (EGP) - OT/SCADA Cybersecurity Scanner for Power Grid Networks

.DESCRIPTION
    Scans power grid, transmission, and substation OT/SCADA subnets for:
      - Named vendor CVEs (Hitachi Energy, ABB, B&R)
      - Hitachi Energy RTU500 series vulnerability exposure
      - Remote-access protocol exposure (RDP, VNC, SSH, Telnet, FTP, HTTP/HTTPS)
      - ICS protocol exposure (DNP3, Modbus, IEC 60870-5-104, IEC 61850, EtherNet/IP, PROFINET, OPC UA)
    Produces severity-tagged (CRITICAL/HIGH/MEDIUM) console output and a timestamped
    JSON report saved to the reports/ directory.

    Reference: CISA Alert AA26-097A | FBI PSA 2026-08-01
    Use only on networks you own or have explicit written authorization to scan.

.PARAMETER Subnet
    Target /24 CIDR subnet (e.g., 192.168.10.0/24). Must be a valid /24 notation.

.PARAMETER TimeoutMs
    TCP connection timeout in milliseconds. Default: 500. Range: 100-5000.

.PARAMETER CveOnly
    Switch. When specified, skips remote-access and ICS protocol checks and
    performs only named CVE port checks (fast-scan mode).

.PARAMETER OutputDir
    Directory for saving the report. Default: .\reports

.EXAMPLE
    .\EGP.ps1 -Subnet 10.10.20.0/24
    Full scan of 10.10.20.0/24 with default 500ms timeout.

.EXAMPLE
    .\EGP.ps1 -Subnet 192.168.100.0/24 -TimeoutMs 1000 -CveOnly
    Fast CVE-only scan of 192.168.100.0/24 with 1000ms timeout.

.EXAMPLE
    .\EGP.ps1 -Subnet 172.16.5.0/24 -OutputDir C:\Reports\EGP
    Full scan saving report to C:\Reports\EGP

.NOTES
    Author  : spinfosecurity
    Version : 1.1.0
    License : MIT
    Project : https://github.com/spinfosecurity/ics-ot-protector/tree/main/scanners/energy-grid
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Target /24 CIDR subnet, e.g. 192.168.1.0/24')]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}/24$')]
    [string]$Subnet,

    [Parameter(Mandatory = $false)]
    [ValidateRange(100, 5000)]
    [int]$TimeoutMs = 500,

    [Parameter(Mandatory = $false)]
    [switch]$CveOnly,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = '.\reports'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SharedRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $SharedRoot '_shared' 'Import-SectorConfig.ps1')
. (Join-Path $SharedRoot '_shared' 'ScannerHelpers.ps1')
. (Join-Path $SharedRoot '_shared' 'ScanEngine.ps1')
. (Join-Path $SharedRoot '_shared' 'Export-ScanReport.ps1')
$script:SectorConfig = Import-SectorConfig -Sector 'energy-grid'
Initialize-EnergyGridConfig -Config $script:SectorConfig

$script:ScanFindings = [System.Collections.Generic.List[pscustomobject]]::new()

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Energy Grid Protector (EGP) v1.1.0" -ForegroundColor Cyan
    Write-Host "  OT/SCADA Cybersecurity Scanner - Power Grid Edition" -ForegroundColor Cyan
    Write-Host "  github.com/spinfosecurity/ics-ot-protector" -ForegroundColor Cyan
    Write-Host "  Ref: CISA AA26-097A | FBI PSA 2026-08-01" -ForegroundColor DarkCyan
    Write-Host "  USE ONLY ON NETWORKS YOU ARE AUTHORIZED TO SCAN" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Write finding to report and console
# ---------------------------------------------------------------------------
function Write-Finding {
    param (
        [Parameter(Mandatory)]
        $Finding
    )

    $script:ScanFindings.Add($Finding)

    $color = Get-SeverityColor $Finding.Severity

    Write-Host "  [$($Finding.Severity)] " -ForegroundColor $color -NoNewline
    Write-Host "$($Finding.Host):$($Finding.Port)" -ForegroundColor White -NoNewline
    Write-Host " - $($Finding.Service)" -ForegroundColor $color
    Write-Host "    $($Finding.Description)" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# MAIN (skipped when $EGP_TEST_MODE is set before dot-sourcing)
# ---------------------------------------------------------------------------
if ($EGP_TEST_MODE -or $global:EGP_TEST_MODE) { return }

Show-Banner

# Validate and prepare output directory
if (-not (Test-Path $OutputDir)) {
    try {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    } catch {
        Write-Error "Cannot create output directory '$OutputDir': $_"
        exit 1
    }
}

$modeLabel   = if ($CveOnly) { 'CVE-ONLY (fast-scan)' } else { 'FULL SCAN' }

Write-Host "[*] Mode       : $modeLabel" -ForegroundColor Cyan
Write-Host "[*] Target     : $Subnet" -ForegroundColor Cyan
Write-Host "[*] Timeout    : ${TimeoutMs}ms per port" -ForegroundColor Cyan
Write-Host "[*] Output Dir : $OutputDir" -ForegroundColor Cyan
Write-Host ""

try {
    $hosts = Get-SubnetHosts -CidrSubnet $Subnet
} catch {
    Write-Error "Subnet parsing failed: $_"
    exit 1
}

$portCatalog = Get-EnergyGridPortCatalogFromConfig -Config $script:SectorConfig -CveOnly:$CveOnly
$script:findingsCount = 0

Invoke-TcpPortScan -Targets $hosts -PortCatalog $portCatalog -TimeoutMs $TimeoutMs -Threads 1 `
    -OnProgress {
        param($TargetHost, $Processed, $Total)
        $pct = [math]::Round(($Processed / $Total) * 100, 1)
        Write-Progress -Activity "EGP Scanning $Subnet" `
            -Status "[$Processed/$Total] Scanning $TargetHost ($pct%)" `
            -PercentComplete $pct
    } `
    -OnFinding {
        param($Finding)
        Write-Finding -Finding $Finding
        $script:findingsCount++
    }

$findings = $script:findingsCount
$hostsScanned = $hosts.Count

Write-Progress -Activity "EGP Scanning $Subnet" -Completed

$exportPaths = Export-ScanReport -Findings @($script:ScanFindings) -OutputDir $OutputDir -Prefix 'EGP-results' `
    -Metadata @{
        sector     = 'energy-grid'
        scanner    = 'Energy Grid Protector'
        version    = '1.1.0'
        scan_mode  = $modeLabel
        target     = $Subnet
        timeout_ms = $TimeoutMs
        reference  = 'CISA Alert AA26-097A | FBI PSA 2026-08-01'
    }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SCAN COMPLETE" -ForegroundColor Green
Write-Host "  Hosts Scanned : $hostsScanned" -ForegroundColor White
Write-Host "  Findings      : $findings" -ForegroundColor $(if ($findings -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Report Saved  : $($exportPaths.ReportPath)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
if ($findings -gt 0) {
    Write-Host "[!] ACTION REQUIRED: Review findings and apply remediations." -ForegroundColor Red
    Write-Host "    See docs/CISA-Reference.md and docs/Threat-Intelligence.md" -ForegroundColor Yellow
}
